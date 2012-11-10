# This is Makefile.am of iwas4gdou (2012-11-10)
#
# Copyright (C) 2010 Imma. <474445006@QQ.com>
#
# iwas4gdou is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

noinst_PROGRAMS = version
version_SOURCES = version.c version.h
sbin_PROGRAMS = iwas4gdou
iwas4gdou_SOURCES = \
  main.c global.h \
  iwas4g.c iwas4g.h \
  pidfile.c pidfile.h \
  md5.c md5.h \
  hmac_md5.c hmac_md5.h \
  rc4.c rc4.h \
  $(NULL)
LDADD = $(PCAP_LIBS)
dist_noinst_man_MANS = iwas4gdou.1
EXTRA_DIST = COPYING README

