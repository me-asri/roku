CC     = gcc
CFLAGS = -std=gnu11 -Wall -O2 -g

SRCS   = $(wildcard *.c)
DEPS   = $(wildcard *.h)
OBJS   = $(SRCS:.c=.o)

TARGET = roku

ifeq ($(PREFIX),)
	PREFIX := /usr/local
endif

.PHONY: clean all install

all: $(TARGET)
	@echo Compiled $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) *.o $(TARGET)

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin/
	install -m 755 roku $(DESTDIR)$(PREFIX)/bin/
