CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -Werror -O2 \
    -fstack-protector-strong \
    -fstack-clash-protection \
    -fcf-protection=full \
    -fPIE -pie \
    -Wl,-z,relro,-z,now,-z,noexecstack \
    -Wl,-z,shstk \
    -Wformat \
    -fno-omit-frame-pointer \
    -fno-common \
    -Wno-unused-parameter \
    -Wno-unused-result

LDFLAGS = -Wl,-z,relro,-z,now,-z,noexecstack -pie

TARGET = noteservice
SRC = vuln.c
FLAG = flag.txt

all: $(TARGET) $(FLAG)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(FLAG):
	echo "flag{ch41n3d_m3m0ry_c0rrupt10n_m4st3ry_2026}" > $@

checksec: $(TARGET)
	@echo "=== Checksec ==="
	@checksec --file=$(TARGET) 2>/dev/null || (echo "checksec not installed"; file $(TARGET); readelf -l $(TARGET) | grep -E "(STACK|GNU_RELRO|GNU_STACK)")

debug: CFLAGS += -g -O0 -DDEBUG
debug: $(TARGET)

run: $(TARGET) $(FLAG)
	./$(TARGET)

test: $(TARGET) $(FLAG)
	timeout 5 ./$(TARGET) &
	sleep 1
	echo "help" | nc localhost 1337
	echo "register testuser" | nc localhost 1337
	echo "create 100" | nc localhost 1337
	echo "write 0 AAAA%lx.%lx.%lx.%lx" | nc localhost 1337
	pkill -f $(TARGET) || true

clean:
	rm -f $(TARGET) $(FLAG)

.PHONY: all checksec debug run test clean