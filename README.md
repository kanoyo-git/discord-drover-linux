# Linux Drover (LD_PRELOAD)

[Русский](#russian) · [English](#english)

---

<a id="russian"></a>

## Русский

### Функционал

- **Обход голосовых UDP-узлов Discord** — полный аналог Windows Drover. Отслеживает UDP-сокеты и модифицирует характерный стартовый пакет голосового чата.

- **TCP через SOCKS5-прокси** — перехват HTTP `CONNECT` и runtime-конвертация в SOCKS5 handshake.

- **TCP HTTP-прокси с авторизацией** — автоматическая вставка заголовка `Proxy-Authorization: Basic` перед `User-Agent:` в первом HTTP-запросе.

- **Сборка мусора** — автоматическое удаление записей о сокетах старше 30 секунд из внутренней таблицы.

### Использование

**Сборка**

```bash
cd discord-drover-linux
make
```

**Запуск**

```bash
# Рядом с .so лежат drover.ini и/или drover-packet.bin
LD_PRELOAD=./libdrover.so discord
```

Или через `~/.config/discord-drover/`:

```bash
mkdir -p ~/.config/discord-drover-linux
cp libdrover.so drover.ini drover-packet.bin ~/.config/discord-drover-linux/
LD_PRELOAD=$HOME/.config/discord-drover-linux/libdrover.so discord
```

**Конфигурация (`drover.ini`)**

Файл ищется сначала рядом с `libdrover.so`, затем в `~/.config/discord-drover-linux/`.

```ini
[drover]
proxy = socks5://127.0.0.1:1080
```

Поддерживаемые форматы:

- `http://host:port`
- `http://login:password@host:port`
- `socks5://host:port`

**Отладка**

```bash
DROVER_DEBUG=1 LD_PRELOAD=./libdrover.so discord
```

**Примечания**

- Работает только с нативным Discord (`.tar.gz`, `.deb`, `.rpm`). Snap и Flatpak блокируют `LD_PRELOAD`.
- Требуется GNU/Linux с glibc.

---

<a id="english"></a>

## English

### Features

- **Discord voice UDP node bypass** — full equivalent of Windows Drover. Monitors UDP sockets and modifies the characteristic voice chat startup packet.

- **TCP via SOCKS5 proxy** — intercepts HTTP `CONNECT` and converts it to SOCKS5 handshake at runtime.

- **TCP HTTP proxy with authorization** — automatically injects the `Proxy-Authorization: Basic` header before `User-Agent:` in the first HTTP request.

- **Garbage collection** — automatically removes socket records older than 30 seconds from the internal table.

### Usage

**Build**

```bash
cd discord-drover-linux
make
```

**Run**

```bash
# drover.ini and/or drover-packet.bin should be next to .so
LD_PRELOAD=./libdrover.so discord
```

Or via `~/.config/discord-drover-linuxr/`:

```bash
mkdir -p ~/.config/discord-drover-linux
cp libdrover.so drover.ini drover-packet.bin ~/.config/discord-drover-linux/
LD_PRELOAD=$HOME/.config/discord-drover-linux/libdrover.so discord
```

**Configuration (`drover.ini`)**

The file is searched first next to `libdrover.so`, then in `~/.config/discord-drover-linux/`.

```ini
[drover]
proxy = socks5://127.0.0.1:1080
```

Supported formats:

- `http://host:port`
- `http://login:password@host:port`
- `socks5://host:port`

**Debug**

```bash
DROVER_DEBUG=1 LD_PRELOAD=./libdrover.so discord
```

**Notes**

- Works only with native Discord (`.tar.gz`, `.deb`, `.rpm`). Snap and Flatpak block `LD_PRELOAD`.
- Requires GNU/Linux with glibc.
