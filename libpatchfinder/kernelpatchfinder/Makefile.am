AM_CFLAGS = -I$(top_srcdir)/include $(libgeneral_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS)
AM_LDFLAGS = $(libgeneral_LIBS) $(libinsn_LIBS)


noinst_LTLIBRARIES = libpatchfinder_kernelpatchfinder.la
libpatchfinder_kernelpatchfinder_la_CFLAGS = $(AM_CFLAGS)
libpatchfinder_kernelpatchfinder_la_CXXFLAGS = $(AM_CXXFLAGS)
libpatchfinder_kernelpatchfinder_la_LIBADD = $(AM_LDFLAGS)
libpatchfinder_kernelpatchfinder_la_SOURCES = kernelpatchfinder.cpp


noinst_LTLIBRARIES += libpatchfinder_kernelpatchfinder64.la
libpatchfinder_kernelpatchfinder_la_LIBADD += libpatchfinder_kernelpatchfinder64.la
libpatchfinder_kernelpatchfinder64_la_CFLAGS = $(AM_CFLAGS)
libpatchfinder_kernelpatchfinder64_la_CXXFLAGS = $(AM_CXXFLAGS)
libpatchfinder_kernelpatchfinder64_la_LIBADD = $(AM_LDFLAGS)
libpatchfinder_kernelpatchfinder64_la_SOURCES =	kernelpatchfinder64.cpp \
											 												 	kernelpatchfinder64_base.cpp \
																								kernelpatchfinder64_iOS9.cpp \
																								kernelpatchfinder64_iOS12.cpp \
																								kernelpatchfinder64_iOS13.cpp \
																								kernelpatchfinder64_iOS15.cpp \
																								kernelpatchfinder64_iOS16.cpp \
																								kernelpatchfinder64_iOS17.cpp

noinst_LTLIBRARIES += libpatchfinder_kernelpatchfinder32.la
libpatchfinder_kernelpatchfinder_la_LIBADD += libpatchfinder_kernelpatchfinder32.la
libpatchfinder_kernelpatchfinder32_la_CFLAGS = $(AM_CFLAGS)
libpatchfinder_kernelpatchfinder32_la_CXXFLAGS = $(AM_CXXFLAGS)
libpatchfinder_kernelpatchfinder32_la_LIBADD = $(AM_LDFLAGS)
libpatchfinder_kernelpatchfinder32_la_SOURCES =	kernelpatchfinder32.cpp \
											 												 	kernelpatchfinder32_base.cpp \
																								kernelpatchfinder32_iOS5.cpp \
																								kernelpatchfinder32_iOS6.cpp \
																								kernelpatchfinder32_iOS8.cpp \
																								kernelpatchfinder32_iOS9.cpp \
																								kernelpatchfinder32_iOS11.cpp
