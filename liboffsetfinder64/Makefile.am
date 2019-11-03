AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/include/liboffsetfinder64 $(libimg4tool_CFLAGS) $(libgeneral_CFLAGS)
AM_LDFLAGS = -L/usr/local/lib/ $(libimg4tool_LIBS) $(libgeneral_LIBS)

lib_LTLIBRARIES = liboffsetfinder64.la

liboffsetfinder64_la_CPPFLAGS = $(AM_CFLAGS)
liboffsetfinder64_la_LIBADD = $(AM_LDFLAGS)
liboffsetfinder64_la_SOURCES = 	insn.cpp \
																vsegment.cpp \
																vmem.cpp \
																patch.cpp \
																patchfinder64.cpp \
																machopatchfinder64.cpp \
																kernelpatchfinder64.cpp \
																ibootpatchfinder64.cpp
