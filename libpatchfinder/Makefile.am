SUBDIRS=ibootpatchfinder kernelpatchfinder

AM_CFLAGS = -I$(top_srcdir)/include $(libimg4tool_CFLAGS) $(libimg3tool_CFLAGS) $(libgeneral_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS)
AM_LDFLAGS = $(libimg4tool_LIBS) $(libimg3tool_LIBS) $(libgeneral_LIBS) $(libinsn_LIBS)

lib_LTLIBRARIES = libpatchfinder.la

libpatchfinder_la_CPPFLAGS = $(AM_CFLAGS)
libpatchfinder_la_LIBADD = $(AM_LDFLAGS) ibootpatchfinder/libpatchfinder_ibootpatchfinder.la

if WITH_KERNELPATCHFINDER
libpatchfinder_la_LIBADD += kernelpatchfinder/libpatchfinder_kernelpatchfinder.la
endif #WITH_KERNELPATCHFINDER

libpatchfinder_la_SOURCES =	patch.cpp \
							StableHash.cpp \
							patchfinder.cpp \
							patchfinder32.cpp \
							patchfinder64.cpp

if WITH_MACHO
libpatchfinder_la_SOURCES +=  machopatchfinder32.cpp \
							                  machopatchfinder64.cpp
endif #WITH_MACHO
