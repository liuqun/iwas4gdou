#	This is a file of iwas4gdou. (2010-09-10)
#
#    Copyright (C) 2010 Imma. <474445006@QQ.com>
#
#    iwas4gdou is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. If not, see <http://www.gnu.org/licenses/>.


all: iwas4gdou iwas4gdou.1

CC      = gcc 
CFLAG   = -O -Wall
INCLUDE = -I.:/usr/local/include/
LIB			= -L.:/usr/local/lib/
LINKLIB = -lpcap

INSTDIR = /usr/local

iwas4gdou: main.o pidfile.o iwas4g.o md5.o rc4.o hmac_md5.o
	$(CC) $(INCLUDE) $(LIB) $(LINKLIB) -o iwas4gdou main.o pidfile.o iwas4g.o md5.o rc4.o hmac_md5.o

main.o: main.c pidfile.h iwas4g.h
	$(CC) $(INCLUDE) $(CFLAG) -c main.c

pidfile.o: pidfile.c
	$(CC) $(INCLUDE) $(CFLAG) -c pidfile.c

iwas4g.o: iwas4g.c global.h md5.h rc4.h hmac_md5.h
	$(CC) $(INCLUDE) $(CFLAG) -c iwas4g.c

md5.o: md5.c global.h md5.h
	$(CC) $(INCLUDE) $(CFLAG) -c md5.c

rc4.o: rc4.c 
	$(CC) $(INCLUDE) $(CFLAG) -c rc4.c

hmacmd5.o: hmac_md5.c global.h md5.h
	$(CC) $(INCLUDE) $(CFLAG) -c hmac_md5.c
	
	
clean:
	rm main.o pidfile.o iwas4g.o md5.o rc4.o hmac_md5.o


install:
	mkdir -p $(INSTDIR)/bin/
	mkdir -p $(INSTDIR)/share/man/man1/
	install -m755 iwas4gdou $(INSTDIR)/bin/iwas4gdou
	install -m755 iwas4gdou.1 $(INSTDIR)/share/man/man1/iwas4gdou.1


uninstall:
	rm -f $(INSTDIR)/bin/iwas4gdou
	rm -f $(INSTDIR)/share/man/man1/iwas4gdou.1*


dist: iwas4gdou-0.1.tar.gz


iwas4gdou-0.1.tar.gz: iwas4gdou iwas4gdou.1
	rm -rf iwas4gdou-0.1
	mkdir iwas4gdou-0.1
	cp *.{c,h} iwas4gdou.1 Makefile README COPYING iwas4gdou-0.1
	tar jcvf $@ iwas4gdou-0.1
	
