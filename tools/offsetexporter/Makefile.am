AM_CFLAGS = -I$(top_srcdir)/include $(libgeneral_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS) $(GLOBAL_CXXFLAGS)
AM_LDFLAGS = $(libgeneral_LIBS)

if WITH_OFFSETEXPORTER

bin_PROGRAMS = offsetexporter

offsetexporter_CFLAGS = $(AM_CFLAGS)
offsetexporter_CXXFLAGS = $(AM_CXXFLAGS)
offsetexporter_LDFLAGS = $(AM_LDFLAGS)
offsetexporter_LDADD = ../../libpatchfinder/libpatchfinder.la
offsetexporter_SOURCES = 	main.cpp \
                            reflector_kernelpatchfinder.cpp


BUILT_SOURCES = reflected_kernelpatchfinder.cpp reflected_patchfinder.cpp


reflected_kernelpatchfinder.cpp: reflected_%.cpp: ${srcdir}/../../include/libpatchfinder/kernelpatchfinder/%.hpp
	python3 ${srcdir}/genreflector.py $< reflected_$*.cpp

reflected_patchfinder.cpp: reflected_%.cpp: ${srcdir}/../../include/libpatchfinder/%.hpp
	python3 ${srcdir}/genreflector.py $< reflected_$*.cpp

CLEANFILES = reflected_kernelpatchfinder.cpp reflected_patchfinder.cpp


endif #WITH_OFFSETEXPORTER