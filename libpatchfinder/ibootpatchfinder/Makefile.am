AM_CFLAGS = -I$(top_srcdir)/include $(libgeneral_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS)
AM_LDFLAGS = $(libgeneral_LIBS) $(libinsn_LIBS)


noinst_LTLIBRARIES = libpatchfinder_ibootpatchfinder.la
libpatchfinder_ibootpatchfinder_la_CFLAGS = $(AM_CFLAGS)
libpatchfinder_ibootpatchfinder_la_CXXFLAGS = $(AM_CXXFLAGS)
libpatchfinder_ibootpatchfinder_la_LIBADD = $(AM_LDFLAGS)
libpatchfinder_ibootpatchfinder_la_SOURCES = ibootpatchfinder.cpp

noinst_LTLIBRARIES += libpatchfinder_ibootpatchfinder64.la
libpatchfinder_ibootpatchfinder_la_LIBADD += libpatchfinder_ibootpatchfinder64.la
libpatchfinder_ibootpatchfinder64_la_CFLAGS = $(AM_CFLAGS)
libpatchfinder_ibootpatchfinder64_la_CXXFLAGS = $(AM_CXXFLAGS)
libpatchfinder_ibootpatchfinder64_la_LIBADD = $(AM_LDFLAGS)
libpatchfinder_ibootpatchfinder64_la_SOURCES =	ibootpatchfinder64.cpp \
											 												 	ibootpatchfinder64_base.cpp \
																								ibootpatchfinder64_iOS7.cpp \
																								ibootpatchfinder64_iOS9.cpp \
																								ibootpatchfinder64_iOS10.cpp \
																								ibootpatchfinder64_iOS12.cpp \
																								ibootpatchfinder64_iOS13.cpp \
																								ibootpatchfinder64_iOS14.cpp \
																								ibootpatchfinder64_iOS15.cpp \
																								ibootpatchfinder64_iOS16.cpp \
																								ibootpatchfinder64_iOS17.cpp

noinst_LTLIBRARIES += libpatchfinder_ibootpatchfinder32.la
libpatchfinder_ibootpatchfinder_la_LIBADD += libpatchfinder_ibootpatchfinder32.la
libpatchfinder_ibootpatchfinder32_la_CFLAGS = $(AM_CFLAGS)
libpatchfinder_ibootpatchfinder32_la_CXXFLAGS = $(AM_CXXFLAGS)
libpatchfinder_ibootpatchfinder32_la_LIBADD = $(AM_LDFLAGS)
libpatchfinder_ibootpatchfinder32_la_SOURCES =	ibootpatchfinder32.cpp \
											 												 	ibootpatchfinder32_base.cpp \
																								ibootpatchfinder32_iOS5.cpp \
																								ibootpatchfinder32_iOS11.cpp \
																								ibootpatchfinder32_iOS12.cpp \
																								ibootpatchfinder32_iOS13.cpp
