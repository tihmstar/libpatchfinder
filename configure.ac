AC_PREREQ([2.69])
AC_INIT([liboffsetfinder64], m4_esyscmd([git rev-list --count HEAD | tr -d '\n']), [tihmstar@gmail.com])

AC_CANONICAL_SYSTEM

AC_CANONICAL_HOST
# Check for operating system
AC_MSG_CHECKING([whether we need platform-specific build settings])
case $host_os in
  darwin* )
        CXXFLAGS+=" -stdlib=libc++ "
        ;;
esac

AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])
AM_PROG_LIBTOOL
AM_INIT_AUTOMAKE

CPPFLAGS+=" -std=c++11 -O3"

CPPFLAGS+=" -D VERSION_COMMIT_COUNT=\\\"$(git rev-list --count HEAD | tr -d '\n')\\\""
CPPFLAGS+=" -D VERSION_COMMIT_SHA=\\\"$(git rev-parse HEAD | tr -d '\n')\\\""
CPPFLAGS+=" -D EXPECTIONNAME=OFexception"

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h unistd.h])

LT_INIT

AC_CONFIG_FILES([Makefile
                 include/Makefile
                 liboffsetfinder64/Makefile
		 liboffsetfinder64.pc])
AC_OUTPUT
