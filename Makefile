CC=gcc
override CFLAGS+=-std=c99 -Wall
PREFIX=/usr/local
LDFLAGS=-L. -lmhash -lmcrypt -lsqlite3 -lbcrypt
.PHONY: crypt_blowfish

all: steel

steel: libbcrypt.a bcrypt.o steel.o status.o cmd_ui.o entries.o backup.o database.o crypto.o
	$(CC) $(CFLAGS) bcrypt.o steel.o status.o database.o entries.o backup.o cmd_ui.o crypto.o -o steel $(LDFLAGS)

libbcrypt.a: crypt_blowfish
	ar r libbcrypt.a crypt_blowfish/*.o

bcrypt.o: bcrypt.c
	$(CC) $(CFLAGS) -c bcrypt.c

crypt_blowfish:
	$(MAKE) -C crypt_blowfish

steel.o: steel.c
	$(CC) $(CFLAGS) -c steel.c

database.o: database.c
	$(CC) $(CFLAGS) -c database.c

entries.o: entries.c
	$(CC) $(CFLAGS) -c entries.c

crypto.o: crypto.c
	$(CC) $(CFLAGS) -c crypto.c

cmd_ui.o: cmd_ui.c
	$(CC) $(CFLAGS) -c cmd_ui.c

status.o: status.c
	$(CC) $(CFLAGS) -c status.c

backup.o: backup.c
	$(CC) $(CFLAGS) -c backup.c

clean:
	rm -f steel
	rm -f *.o
	rm -f libbcrypt.a
	cd crypt_blowfish; $(MAKE) clean

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

