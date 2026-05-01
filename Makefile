CC = gcc
CFLAGS = -fPIC -Wall -O2 -D_GNU_SOURCE
LDFLAGS = -shared -ldl -lpthread

TARGET = libdrover.so

all: $(TARGET)

$(TARGET): drover.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	mkdir -p $(HOME)/.config/discord-drover
	cp $(TARGET) $(HOME)/.config/discord-drover/
	@echo "Copy drover.ini and drover-packet.bin to $(HOME)/.config/discord-drover/ if needed"
