AM_CFLAGS = -I$(top_srcdir)/include $(libgeneral_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS) $(GLOBAL_CXXFLAGS)
AM_LDFLAGS = $(libgeneral_LIBS)


if WITH_BINRIDER

bin_PROGRAMS = binrider

binrider_CFLAGS = $(AM_CFLAGS)
binrider_CXXFLAGS = $(AM_CXXFLAGS)
binrider_LDFLAGS = $(AM_LDFLAGS)
binrider_LDADD = ../../libpatchfinder/libpatchfinder.la
binrider_SOURCES = 	main.cpp

endif #WITH_BINRIDER