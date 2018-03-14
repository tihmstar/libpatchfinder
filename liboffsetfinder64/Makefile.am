AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/include/liboffsetfinder64 -I$(top_srcdir)/external/img4tool/img4tool -I$(top_srcdir)/external/libplist/include
AM_LDFLAGS = -L/usr/local/lib/

lib_LTLIBRARIES = liboffsetfinder64.la 

liboffsetfinder64_la_CPPFLAGS = $(AM_CFLAGS)
liboffsetfinder64_la_LIBADD = $(AM_LDFLAGS)
liboffsetfinder64_la_SOURCES = liboffsetfinder64.cpp exception.cpp insn.cpp patch.cpp
