AM_CFLAGS = -I$(top_srcdir)/include $(libgeneral_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS)
AM_LDFLAGS = $(libgeneral_LIBS) $(libinsn_LIBS)

if WITH_TXMPATCHFINDER
noinst_LTLIBRARIES = libpatchfinder_txmpatchfinder.la
libpatchfinder_txmpatchfinder_la_CFLAGS = $(AM_CFLAGS)
libpatchfinder_txmpatchfinder_la_CXXFLAGS = $(AM_CXXFLAGS)
libpatchfinder_txmpatchfinder_la_LIBADD = $(AM_LDFLAGS)
libpatchfinder_txmpatchfinder_la_SOURCES = txmpatchfinder.cpp


noinst_LTLIBRARIES += libpatchfinder_txmpatchfinder64.la
libpatchfinder_txmpatchfinder_la_LIBADD += libpatchfinder_txmpatchfinder64.la
libpatchfinder_txmpatchfinder64_la_CFLAGS = $(AM_CFLAGS)
libpatchfinder_txmpatchfinder64_la_CXXFLAGS = $(AM_CXXFLAGS)
libpatchfinder_txmpatchfinder64_la_LIBADD = $(AM_LDFLAGS)
libpatchfinder_txmpatchfinder64_la_SOURCES =	txmpatchfinder64.cpp \
                                              txmpatchfinder64_base.cpp

endif #WITH_TXMPATCHFINDER