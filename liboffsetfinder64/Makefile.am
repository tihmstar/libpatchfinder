AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/include/liboffsetfinder64 -I$(top_srcdir)/external/img4tool/img4tool -I$(top_srcdir)/external/libplist/include  -I$(top_srcdir)/external/libgeneral/include
AM_LDFLAGS = -L/usr/local/lib/

lib_LTLIBRARIES = liboffsetfinder64.la 

liboffsetfinder64_la_CPPFLAGS = $(AM_CFLAGS)
liboffsetfinder64_la_LIBADD = $(AM_LDFLAGS)
liboffsetfinder64_la_SOURCES = liboffsetfinder64.cpp insn.cpp patch.cpp $(top_srcdir)/external/libgeneral/libgeneral/exception.cpp
