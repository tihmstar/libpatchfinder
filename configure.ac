AC_PREREQ([2.69])
AC_INIT([liboffsetfinder64], m4_esyscmd([git rev-list --count HEAD | tr -d '\n']), [tihmstar@gmail.com])

AC_CANONICAL_SYSTEM
AC_CANONICAL_HOST
AM_PROG_LIBTOOL

AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

AC_DEFINE([VERSION_COMMIT_COUNT], "m4_esyscmd([git rev-list --count HEAD | tr -d '\n'])", [Git commit count])
AC_DEFINE([VERSION_COMMIT_SHA], "m4_esyscmd([git rev-parse HEAD | tr -d '\n'])", [Git commit sha])
AC_SUBST([VERSION_COMMIT_COUNT], ["m4_esyscmd([git rev-list --count HEAD | tr -d '\n'])"])
AC_SUBST([VERSION_COMMIT_SHA], ["m4_esyscmd([git rev-parse HEAD | tr -d '\n'])"])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

# Check for operating system
AC_MSG_CHECKING([whether we need platform-specific build settings])
case $host_os in
  darwin* )
        CXXFLAGS+=" -stdlib=libc++ "
        ;;
esac


CXXFLAGS+=" -std=c++11 -O3"
CFLAGS+=" -std=c11"
CXXFLAGS+=" -D EXPECTIONNAME=OFexception"

# Checks for libraries.
IMG4TOOL_REQUIRES_STR="libimg4tool >= 159"
LIBGENERAL_REQUIRES_STR="libgeneral >= 26"
PKG_CHECK_MODULES(libimg4tool, $IMG4TOOL_REQUIRES_STR, have_img4tool=yes, have_img4tool=no)
PKG_CHECK_MODULES(libgeneral, $LIBGENERAL_REQUIRES_STR)

AC_SUBST([libgeneral_requires], [$LIBGENERAL_REQUIRES_STR])


AC_ARG_WITH([img4tool],
            [AS_HELP_STRING([--without-img4tool],
            [do not build with img4tool @<:@default=yes@:>@])],
            [with_img4tool=no],
            [with_img4tool=yes])

if test "x$with_img4tool" == "xyes"; then
  if test "x$have_img4tool" = "xyes"; then
    AC_DEFINE(HAVE_IMG4TOOL, 1, [Define if you have img4tool])
    AC_SUBST([img4tool_requires], [$IMG4TOOL_REQUIRES_STR])
    AC_SUBST(libimg4tool_CFLAGS)
    AC_SUBST(libimg4tool_LIBS)
  else
    echo "*** Note: img4tool has been disabled ***"
  fi
else
  if test "x$with_img4tool" == "xyes"; then
    AC_MSG_ERROR([requested building with img4tool, but library could not be found])
  fi
fi

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h unistd.h])

LT_INIT

AC_CONFIG_FILES([Makefile
                 include/Makefile
                 liboffsetfinder64/Makefile
		             liboffsetfinder64.pc])
AC_OUTPUT

echo "
Configuration for $PACKAGE-$VERSION:
-------------------------------------------

  install prefix ..........: $prefix
  have img4tool ...........: $with_img4tool"

echo "  compiler ................: ${CC}

  Now type 'make' to build $PACKAGE-$VERSION,
  and then 'make install' for installation.
"
