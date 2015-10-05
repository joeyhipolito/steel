CC=gcc
override CFLAGS+=-std=c99 -Wall
PREFIX=/usr/local
LDFLAGS=-lmhash -lmcrypt -lsqlite3

all: steel

steel: bcrypt.a steel.o database.o entries.o crypto.o
	$(CC) $(CFLAGS) steel.o database.o entries.o crypto.o -o steel $(LDFLAGS)

bcrypt.a:
	cd bcrypt; $(MAKE)

steel.o: steel.c
	$(CC) $(CFLAGS) -c steel.c

database.o: database.c
	$(CC) $(CFLAGS) -c database.c

entries.o: entries.c
	$(CC) $(CFLAGS) -c entries.c

crypto.o: crypto.c
	$(CC) $(CFLAGS) -c crypto.c

clean:
	rm steel
	rm *.o
	cd bcrypt; $(MAKE) clean

install: all
	if [ ! -d $(PREFIX)/share/man/man1 ];then	\
		mkdir -p $(PREFIX)/share/man/man1;	\
	fi
	cp memo.1 $(PREFIX)/share/man/man1/
	gzip -f $(PREFIX)/share/man/man1/steel.1
	cp memo $(PREFIX)/bin/

uninstall:
	rm $(PREFIX)/bin/steel
	rm $(PREFIX)/share/man/man1/steel.1.gz

