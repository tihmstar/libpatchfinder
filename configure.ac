AC_PREREQ([2.69])
AC_INIT([liboffsetfinder64], [m4_esyscmd([git rev-list --count HEAD])], [tihmstar@gmail.com])
AC_CONFIG_SRCDIR([liboffsetfinder64/liboffsetfinder64.hpp])
AC_CONFIG_HEADERS([config.h])
AM_PROG_LIBTOOL

AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE(liboffsetfinder64, [m4_esyscmd([git rev-list --count HEAD])])

# Checks for programs.
AC_PROG_CXX
CPPFLAGS+=" -std=c++11 -O3"
CFLAGS+=" -std=c11 -O3"
AC_PROG_CC

# Check for operating system
AC_MSG_CHECKING([whether we need platform-specific build settings])
case $host_os in
  darwin* )
        CXXFLAGS+=" -stdlib=libc++"
        ;;
esac

AC_CONFIG_MACRO_DIRS([m4])

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC

AC_CONFIG_SUBDIRS([external/img4tool])
AC_CONFIG_FILES([Makefile
                 include/Makefile
                 liboffsetfinder64/Makefile
		 liboffsetfinder64.pc])

AC_OUTPUT
