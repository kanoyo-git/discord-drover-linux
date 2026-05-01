#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <limits.h>
#include <ctype.h>
#include <stdarg.h>

/* ========================================================================
   Константы
   ======================================================================== */
#define PACKET_FILENAME   "drover-packet.bin"
#define OPTIONS_FILENAME  "drover.ini"
#define MAX_FD            65536
#define GC_INTERVAL_SEC   30

/* ========================================================================
   Структуры
   ======================================================================== */
typedef struct {
    int  active;
    int  is_udp;
    int  is_tcp;
    int  has_sent;
    int  fake_http_proxy_flag;
    struct timespec created_at;
} fd_state_t;

typedef struct {
    int   specified;
    char  protocol[16];
    char  login[256];
    char  password[256];
    char  host[256];
    int   port;
    int   is_http;
    int   is_socks5;
    int   is_auth;
} proxy_value_t;

/* ========================================================================
   Глобальные переменные
   ======================================================================== */
static fd_state_t      g_map[MAX_FD];
static pthread_mutex_t g_map_lock = PTHREAD_MUTEX_INITIALIZER;

static proxy_value_t   g_proxy;
static char            g_self_dir[PATH_MAX] = {0};
static int             g_init_done = 0;

/* Перехваченные функции */
static int     (*real_socket)(int, int, int) = NULL;
static ssize_t (*real_send)(int, const void *, size_t, int) = NULL;
static ssize_t (*real_recv)(int, void *, size_t, int) = NULL;
static ssize_t (*real_sendto)(int, const void *, size_t, int,
                               const struct sockaddr *, socklen_t) = NULL;
static ssize_t (*real_sendmsg)(int, const struct msghdr *, int) = NULL;
static int     (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;

/* ========================================================================
   Лог (опционально, включается переменной DROVER_DEBUG)
   ======================================================================== */
static void drover_log(const char *fmt, ...)
{
    if (!getenv("DROVER_DEBUG")) return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[drover] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

/* ========================================================================
   Определение папки, где лежит .so (через dladdr)
   ======================================================================== */
static void init_self_dir(void)
{
    if (g_self_dir[0]) return;
    Dl_info info;
    if (dladdr((void*)&real_socket, &info) && info.dli_fname) {
        const char *p = info.dli_fname;
        const char *last = strrchr(p, '/');
        if (last) {
            size_t len = (size_t)(last - p) + 1;
            if (len < PATH_MAX) {
                memcpy(g_self_dir, p, len);
                g_self_dir[len] = '\0';
            }
        }
    }
    if (!g_self_dir[0])
        strcpy(g_self_dir, "./");
}

/* ========================================================================
   Чтение drover.ini
   ======================================================================== */
static void parse_proxy(const char *url)
{
    if (!url || !*url) return;

    memset(&g_proxy, 0, sizeof(g_proxy));
    g_proxy.specified = 1;

    const char *p = url;
    char proto[16] = "";

    const char *slash = strstr(p, "://");
    if (slash) {
        size_t plen = slash - p;
        if (plen && plen < sizeof(proto)) {
            memcpy(proto, p, plen);
            proto[plen] = '\0';
            p = slash + 3;
        }
    }

    for (size_t i = 0; proto[i]; i++)
        proto[i] = (char)tolower((unsigned char)proto[i]);

    if (!proto[0] || strcmp(proto, "https") == 0)
        strcpy(proto, "http");

    strcpy(g_proxy.protocol, proto);
    g_proxy.is_http  = (strcmp(proto, "http") == 0);
    g_proxy.is_socks5 = (strcmp(proto, "socks5") == 0);

    /* auth? */
    const char *at = strchr(p, '@');
    if (at) {
        char auth[512];
        size_t alen = at - p;
        if (alen && alen < sizeof(auth)) {
            memcpy(auth, p, alen);
            auth[alen] = '\0';
            char *colon = strchr(auth, ':');
            if (colon) {
                *colon = '\0';
                strcpy(g_proxy.login, auth);
                strcpy(g_proxy.password, colon + 1);
                g_proxy.is_auth = 1;
            }
            p = at + 1;
        }
    }

    /* host:port */
    const char *col = strrchr(p, ':');
    if (col) {
        size_t hlen = col - p;
        if (hlen && hlen < sizeof(g_proxy.host)) {
            memcpy(g_proxy.host, p, hlen);
            g_proxy.host[hlen] = '\0';
            g_proxy.port = atoi(col + 1);
        }
    } else {
        strcpy(g_proxy.host, p);
        g_proxy.port = g_proxy.is_http ? 8080 : 1080;
    }
}

static void load_config(void)
{
    char path[PATH_MAX];
    FILE *f = NULL;

    /* 1. Рядом с .so */
    snprintf(path, sizeof(path), "%s%s", g_self_dir, OPTIONS_FILENAME);
    f = fopen(path, "r");

    /* 2. ~/.config/discord-drover/ */
    if (!f) {
        const char *home = getenv("HOME");
        if (home) {
            snprintf(path, sizeof(path), "%s/.config/discord-drover/%s",
                     home, OPTIONS_FILENAME);
            f = fopen(path, "r");
        }
    }

    if (!f) return;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        /* Удаляем \n */
        size_t len = strlen(line);
        while (len && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';

        /* Ищем proxy = ... */
        char *key = line;
        while (*key == ' ' || *key == '\t') key++;
        if (strncasecmp(key, "proxy", 5) != 0) continue;

        char *eq = strchr(key, '=');
        if (!eq) continue;
        char *val = eq + 1;
        while (*val == ' ' || *val == '\t') val++;
        parse_proxy(val);
        drover_log("loaded proxy: %s://%s:%d", g_proxy.protocol,
                   g_proxy.host, g_proxy.port);
    }
    fclose(f);
}

/* ========================================================================
   Менеджер сокетов (аналог TSocketManager)
   ======================================================================== */
static void fd_collect_garbage(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    for (int i = 0; i < MAX_FD; i++) {
        if (!g_map[i].active) continue;
        if (now.tv_sec - g_map[i].created_at.tv_sec > GC_INTERVAL_SEC)
            memset(&g_map[i], 0, sizeof(g_map[i]));
    }
}

static void fd_add(int fd, int sock_type, int protocol)
{
    if (fd < 0 || fd >= MAX_FD) return;

    int is_tcp = (sock_type == SOCK_STREAM) &&
                 ((protocol == IPPROTO_TCP) || (protocol == 0));
    int is_udp = (sock_type == SOCK_DGRAM) &&
                 ((protocol == IPPROTO_UDP) || (protocol == 0));
    if (!is_tcp && !is_udp) return;

    pthread_mutex_lock(&g_map_lock);
    fd_collect_garbage();
    memset(&g_map[fd], 0, sizeof(g_map[fd]));
    g_map[fd].active = 1;
    g_map[fd].is_tcp = is_tcp;
    g_map[fd].is_udp = is_udp;
    g_map[fd].has_sent = 0;
    g_map[fd].fake_http_proxy_flag = 0;
    clock_gettime(CLOCK_MONOTONIC, &g_map[fd].created_at);
    pthread_mutex_unlock(&g_map_lock);

    drover_log("tracked fd=%d tcp=%d udp=%d", fd, is_tcp, is_udp);
}

static int fd_is_first_send(int fd, fd_state_t *out)
{
    if (fd < 0 || fd >= MAX_FD) return 0;

    pthread_mutex_lock(&g_map_lock);
    if (!g_map[fd].active || g_map[fd].has_sent) {
        pthread_mutex_unlock(&g_map_lock);
        return 0;
    }
    g_map[fd].has_sent = 1;
    if (out) memcpy(out, &g_map[fd], sizeof(*out));
    pthread_mutex_unlock(&g_map_lock);
    return 1;
}

static void fd_set_fake_http_proxy(int fd)
{
    if (fd < 0 || fd >= MAX_FD) return;
    pthread_mutex_lock(&g_map_lock);
    if (g_map[fd].active) g_map[fd].fake_http_proxy_flag = 1;
    pthread_mutex_unlock(&g_map_lock);
}

static int fd_reset_fake_http_proxy(int fd)
{
    if (fd < 0 || fd >= MAX_FD) return 0;
    pthread_mutex_lock(&g_map_lock);
    if (!g_map[fd].active || !g_map[fd].fake_http_proxy_flag) {
        pthread_mutex_unlock(&g_map_lock);
        return 0;
    }
    g_map[fd].fake_http_proxy_flag = 0;
    pthread_mutex_unlock(&g_map_lock);
    return 1;
}

/* ========================================================================
   Base64 (минимальная реализация для Proxy-Authorization)
   ======================================================================== */
static const char b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *base64_encode(const unsigned char *in, size_t in_len, size_t *out_len)
{
    size_t olen = 4 * ((in_len + 2) / 3);
    char *out = malloc(olen + 1);
    if (!out) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < in_len; ) {
        unsigned a = i < in_len ? in[i++] : 0;
        unsigned b = i < in_len ? in[i++] : 0;
        unsigned c = i < in_len ? in[i++] : 0;
        unsigned triple = (a << 16) | (b << 8) | c;
        out[j++] = b64chars[(triple >> 18) & 0x3F];
        out[j++] = b64chars[(triple >> 12) & 0x3F];
        out[j++] = b64chars[(triple >> 6)  & 0x3F];
        out[j++] = b64chars[ triple        & 0x3F];
    }
    for (size_t k = 0; k < (3 - in_len % 3) % 3; k++)
        out[olen - 1 - k] = '=';
    out[olen] = '\0';
    if (out_len) *out_len = olen;
    return out;
}

/* ========================================================================
   UDP Voice Node (аналог MyWSASendTo)
   ======================================================================== */
static void voice_inject_packet(int sockfd,
                                const struct sockaddr *dest_addr,
                                socklen_t addrlen)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s%s", g_self_dir, PACKET_FILENAME);

    int fd = open(path, O_RDONLY);
    if (fd < 0) return;

    struct stat st;
    if (fstat(fd, &st) == 0 && st.st_size > 0) {
        char *data = malloc(st.st_size);
        if (data) {
            if (read(fd, data, st.st_size) == st.st_size) {
                drover_log("injecting %ld bytes from %s", (long)st.st_size, PACKET_FILENAME);
                real_sendto(sockfd, data, st.st_size, 0, dest_addr, addrlen);
            }
            free(data);
        }
    }
    close(fd);
}

static void voice_builtin_manipulation(int sockfd,
                                       const struct sockaddr *dest_addr,
                                       socklen_t addrlen)
{
    unsigned char zero = 0, one = 1;
    drover_log("sending builtin UDP manipulation (0x00, 0x01, sleep 50ms)");
    real_sendto(sockfd, &zero, 1, 0, dest_addr, addrlen);
    real_sendto(sockfd, &one,  1, 0, dest_addr, addrlen);
    usleep(50000);
}

/* ========================================================================
   TCP SOCKS5 (аналог ConvertHttpToSocks5)
   ======================================================================== */
static int socks5_do_handshake(int sockfd, const char *target_host, int target_port)
{
    unsigned char req1[] = {0x05, 0x01, 0x00};
    if (real_send(sockfd, req1, 3, 0) != 3) return 0;

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sockfd, &fds);
    struct timeval tv = {10, 0};
    if (select(sockfd + 1, &fds, NULL, NULL, &tv) < 1) return 0;

    unsigned char resp1[2];
    if (real_recv(sockfd, resp1, 2, 0) != 2) return 0;
    if (resp1[0] != 0x05 || resp1[1] != 0x00) return 0;

    unsigned char req2[512];
    size_t hlen = strlen(target_host);
    if (hlen > 255) return 0;

    req2[0] = 0x05;          /* VER  */
    req2[1] = 0x01;          /* CMD = CONNECT */
    req2[2] = 0x00;          /* RSV  */
    req2[3] = 0x03;          /* ATYP = DOMAINNAME */
    req2[4] = (unsigned char)hlen;
    memcpy(req2 + 5, target_host, hlen);
    req2[5 + hlen] = (unsigned char)(target_port >> 8);
    req2[6 + hlen] = (unsigned char)(target_port & 0xFF);

    size_t req_len = 7 + hlen;
    if (real_send(sockfd, req2, req_len, 0) != (ssize_t)req_len) return 0;

    fd_set_fake_http_proxy(sockfd);
    return 1;
}

/* ========================================================================
   TCP HTTP Proxy Authorization (аналог AddHttpProxyAuthorizationHeader)
   ======================================================================== */
static ssize_t http_inject_auth(int sockfd, const void *buf, size_t len, int flags)
{
    if (!g_proxy.is_http || !g_proxy.is_auth) return -1;

    const char *b = buf;
    const char *ua = strcasestr(b, "\r\nUser-Agent:");
    if (!ua) return -1;

    const char *ua_end = strstr(ua + 2, "\r\n");
    if (!ua_end) return -1;

    size_t ua_len = ua_end - ua; /* длина заголовка User-Agent: ... */

    /* Формируем Proxy-Authorization */
    char creds[512];
    snprintf(creds, sizeof(creds), "%s:%s", g_proxy.login, g_proxy.password);
    size_t creds_len = strlen(creds);
    size_t b64_len = 0;
    char *b64 = base64_encode((unsigned char*)creds, creds_len, &b64_len);
    if (!b64) return -1;

    char auth_hdr[1024];
    int ah_len = snprintf(auth_hdr, sizeof(auth_hdr),
                          "Proxy-Authorization: Basic %s", b64);
    free(b64);
    if (ah_len < 0 || (size_t)ah_len >= sizeof(auth_hdr)) return -1;

    /* Нам нужно, чтобы длина injected заголовка + filler == длина User-Agent */
    int filler = (int)ua_len - ah_len - 2; /* -2 для \r\n перед filler */
    if (filler < 6) return -1; /* как в оригинале Drover */

    /* Собираем новый буфер */
    size_t prefix_len = ua - b;
    size_t suffix_len = len - prefix_len - ua_len;
    size_t new_len = prefix_len + ah_len + 2 + filler + suffix_len;

    char *newbuf = malloc(new_len);
    if (!newbuf) return -1;

    char *p = newbuf;
    memcpy(p, b, prefix_len); p += prefix_len;
    memcpy(p, auth_hdr, ah_len); p += ah_len;
    *p++ = '\r'; *p++ = '\n';
    memset(p, 'X', filler - 5); p += filler - 5;
    memcpy(p, "\r\nX: ", 5); p += 5;
    memcpy(p, ua_end, suffix_len); p += suffix_len;

    drover_log("injected Proxy-Authorization header (%d bytes)", ah_len);
    ssize_t ret = real_send(sockfd, newbuf, new_len, flags);
    free(newbuf);
    return (ret == (ssize_t)new_len) ? (ssize_t)len : ret;
}

/* ========================================================================
   Перехваченные функции
   ======================================================================== */
int socket(int domain, int type, int protocol)
{
    if (!real_socket) real_socket = dlsym(RTLD_NEXT, "socket");
    int fd = real_socket(domain, type, protocol);
    if (fd >= 0 && (domain == AF_INET || domain == AF_INET6)) {
        int base_type = type & 0xF; /* маска флагов SOCK_CLOEXEC/SOCK_NONBLOCK */
        fd_add(fd, base_type, protocol);
    }
    return fd;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen)
{
    if (!real_sendto) real_sendto = dlsym(RTLD_NEXT, "sendto");

    fd_state_t st;
    if (fd_is_first_send(sockfd, &st) && st.is_udp && len == 74) {
        drover_log("UDP first-send fd=%d len=%zu, applying voice node bypass", sockfd, len);
        voice_inject_packet(sockfd, dest_addr, addrlen);
        voice_builtin_manipulation(sockfd, dest_addr, addrlen);
    }

    return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    if (!real_sendmsg) real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");

    /* Считаем общую длину iovec */
    size_t total = 0;
    for (size_t i = 0; i < msg->msg_iovlen; i++)
        total += msg->msg_iov[i].iov_len;

    fd_state_t st;
    if (fd_is_first_send(sockfd, &st) && st.is_udp && total == 74) {
        drover_log("UDP first-send fd=%d sendmsg total=%zu", sockfd, total);
        if (msg->msg_name && msg->msg_namelen > 0) {
            voice_inject_packet(sockfd,
                                (const struct sockaddr *)msg->msg_name,
                                msg->msg_namelen);
            voice_builtin_manipulation(sockfd,
                                       (const struct sockaddr *)msg->msg_name,
                                       msg->msg_namelen);
        }
    }

    return real_sendmsg(sockfd, msg, flags);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    if (!real_send) real_send = dlsym(RTLD_NEXT, "send");

    fd_state_t st;
    if (fd_is_first_send(sockfd, &st) && st.is_tcp) {
        /* SOCKS5 conversion */
        if (g_proxy.is_socks5 && len >= 8 &&
            strncasecmp(buf, "CONNECT ", 8) == 0) {
            char sbuf[1024];
            size_t copy = len < sizeof(sbuf)-1 ? len : sizeof(sbuf)-1;
            memcpy(sbuf, buf, copy);
            sbuf[copy] = '\0';

            char host[256];
            int port = 0;
            if (sscanf(sbuf, "CONNECT %255[^:]:%d", host, &port) == 2) {
                drover_log("intercepted HTTP CONNECT -> SOCKS5 for %s:%d", host, port);
                if (socks5_do_handshake(sockfd, host, port))
                    return (ssize_t)len; /* обманули caller */
            }
        }

        /* HTTP Proxy Authorization */
        if (g_proxy.is_http && g_proxy.is_auth) {
            ssize_t r = http_inject_auth(sockfd, buf, len, flags);
            if (r >= 0) return r;
        }
    }

    return real_send(sockfd, buf, len, flags);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    if (!real_recv) real_recv = dlsym(RTLD_NEXT, "recv");
    ssize_t n = real_recv(sockfd, buf, len, flags);
    if (n > 0 && fd_reset_fake_http_proxy(sockfd)) {
        /* Подменяем SOCKS5 ответ на HTTP/1.1 200 Connection Established */
        if ((size_t)n >= 10 &&
            ((unsigned char*)buf)[0] == 0x05 &&
            ((unsigned char*)buf)[1] == 0x00 &&
            ((unsigned char*)buf)[2] == 0x00) {
            const char *http200 = "HTTP/1.1 200 Connection Established\r\n\r\n";
            size_t hlen = strlen(http200);
            if (hlen <= len) {
                memcpy(buf, http200, hlen);
                drover_log("faked SOCKS5 response -> HTTP 200");
                return (ssize_t)hlen;
            }
        }
    }
    return n;
}

/* ========================================================================
   Инициализация
   ======================================================================== */
__attribute__((constructor))
static void drover_init(void)
{
    if (g_init_done) return;
    g_init_done = 1;

    init_self_dir();
    load_config();

    real_socket  = dlsym(RTLD_NEXT, "socket");
    real_send    = dlsym(RTLD_NEXT, "send");
    real_recv    = dlsym(RTLD_NEXT, "recv");
    real_sendto  = dlsym(RTLD_NEXT, "sendto");
    real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    real_connect = dlsym(RTLD_NEXT, "connect");

    drover_log("initialized, self_dir=%s proxy=%s", g_self_dir,
               g_proxy.specified ? g_proxy.host : "none");
}
