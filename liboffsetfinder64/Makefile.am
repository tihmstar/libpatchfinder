AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/include/liboffsetfinder64  -I$(top_srcdir)/external/libgeneral/include $(libimg4tool_CFLAGS)
AM_LDFLAGS = -L/usr/local/lib/ $(libimg4tool_LIBS)

lib_LTLIBRARIES = liboffsetfinder64.la

liboffsetfinder64_la_CPPFLAGS = $(AM_CFLAGS)
liboffsetfinder64_la_LIBADD = $(AM_LDFLAGS)
liboffsetfinder64_la_SOURCES = $(top_srcdir)/external/libgeneral/libgeneral/exception.cpp \
																insn.cpp \
																vsegment.cpp \
																vmem.cpp \
																patch.cpp \
																patchfinder64.cpp \
																machopatchfinder64.cpp \
																kernelpatchfinder64.cpp \
																ibootpatchfinder64.cpp
