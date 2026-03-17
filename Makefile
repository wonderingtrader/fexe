CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=c99 -pedantic
TARGET  = fexe
SRC     = fexe.c

ifeq ($(OS),Windows_NT)
    TARGET  = fexe.exe
    CFLAGS += -D_WIN32
endif

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

install: $(TARGET)
	@if [ "$(shell uname)" = "Darwin" ] || [ "$(shell uname)" = "Linux" ]; then \
		cp $(TARGET) /usr/local/bin/$(TARGET); \
		chmod +x /usr/local/bin/$(TARGET); \
		echo "Installed to /usr/local/bin/fexe"; \
	else \
		echo "Copy $(TARGET) to a directory in your PATH"; \
	fi

clean:
	rm -f $(TARGET) fexe.exe
