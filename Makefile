CC=gcc
override CFLAGS+=-std=c99 -Wall
PREFIX=/usr/local
LDFLAGS=-lsteek

all: steel

steel: cmd_ui.o
	$(CC) $(CFLAGS) steel.o cmd_ui.o -o steel $(LDFLAGS)

steel.o: steel.c
	$(CC) $(CFLAGS) -c steel.c

cmd_ui.o: cmd_ui.c
	$(CC) $(CFLAGS) -c cmd_ui.c

clean:
	rm -f steel
	rm -f *.o

install: all
	if [ ! -d $(PREFIX)/share/man/man1 ];then	\
		mkdir -p $(PREFIX)/share/man/man1;	\
	fi
	cp steel.1 $(PREFIX)/share/man/man1/
	gzip -f $(PREFIX)/share/man/man1/steel.1
	cp steel $(PREFIX)/bin/

uninstall:
	rm $(PREFIX)/bin/steel
	rm $(PREFIX)/share/man/man1/steel.1.gz

