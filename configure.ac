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
AC_PROG_CXX([clang++])
AC_PROG_CC([clang])

# Check for operating system
AC_MSG_CHECKING([whether we need platform-specific build settings])
case $host_os in
  darwin* )
        AC_MSG_RESULT([${host_os}])
        CXXFLAGS+=" -stdlib=libc++ "
        ;;
  *mingw32*|*cygwin*|*msys*)
        AC_MSG_RESULT([${host_os}])
        win32=true
        LDFLAGS+=" -no-undefined -lws2_32"
        ;;
esac


CXXFLAGS+=" -std=c++20 -O3"
CFLAGS+=" -std=c11"
CXXFLAGS+=" -D EXPECTIONNAME=OFexception"

# Checks for libraries.
IMG4TOOL_REQUIRES_STR="libimg4tool >= 198"
IMG3TOOL_REQUIRES_STR="libimg3tool >= 2"
LIBGENERAL_REQUIRES_STR="libgeneral >= 65"
LIBINSN_REQUIRES_STR="libinsn >= 38"
PKG_CHECK_MODULES(libimg4tool, $IMG4TOOL_REQUIRES_STR, have_img4tool=yes, have_img4tool=no)
PKG_CHECK_MODULES(libimg3tool, $IMG3TOOL_REQUIRES_STR, have_img3tool=yes, have_img3tool=no)
PKG_CHECK_MODULES(libgeneral, $LIBGENERAL_REQUIRES_STR)
PKG_CHECK_MODULES(libinsn, $LIBINSN_REQUIRES_STR)

AC_SUBST([libgeneral_requires], [$LIBGENERAL_REQUIRES_STR])
AC_SUBST([libinsn_requires], [$LIBINSN_REQUIRES_STR])

AC_ARG_ENABLE([debug],
            [AS_HELP_STRING([--enable-debug],
            [enable debug build(default is no)])],
            [debug_build=true],
            [debug_build=false])

AC_ARG_WITH([img4tool],
            [AS_HELP_STRING([--without-img4tool],
            [do not build with img4tool @<:@default=yes@:>@])],
            [with_img4tool=no],
            [with_img4tool=yes])

AC_ARG_WITH([img3tool],
            [AS_HELP_STRING([--without-img3tool],
            [do not build with img3tool @<:@default=yes@:>@])],
            [with_img3tool=no],
            [with_img3tool=yes])

AC_ARG_WITH([macho],
            [AS_HELP_STRING([--without-macho],
            [do not build with macho @<:@default=yes@:>@])],
            [with_macho=no],
            [with_macho=yes])

AC_ARG_ENABLE([asan],
            [AS_HELP_STRING([--enable-asan],
            [enable ASAN build(default is no)])],
            [asan_build=true],
            [asan_build=false])

AC_ARG_WITH([wtfpwndfu],
            [AS_HELP_STRING([--with-wtfpwndfu],
            [build with wtfpwndfu @<:@default=no@:>@])],
            [with_wtfpwndfu=yes],
            [with_wtfpwndfu=no])

AC_ARG_WITH([binrider],
            [AS_HELP_STRING([--with-binrider],
            [do build with binrider @<:@default=no@:>@])],
            [with_binrider=yes],
            [with_binrider=no])

AC_ARG_WITH([offsetexporter],
            [AS_HELP_STRING([--with-offsetexporter],
            [do build with offsetexporter @<:@default=no@:>@])],
            [with_offsetexporter=yes],
            [with_offsetexporter=no])

AM_CONDITIONAL(WITH_BINRIDER, test x$with_binrider == xyes)
AM_CONDITIONAL(WITH_OFFSETEXPORTER, test x$with_offsetexporter == xyes)

if test "x$have_img4tool" == "xyes"; then
  if test "x$with_img4tool" = "xyes"; then
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

if test "x$have_img3tool" == "xyes"; then
  if test "x$with_img3tool" = "xyes"; then
    AC_DEFINE(HAVE_IMG3TOOL, 1, [Define if you have img3tool])
    AC_SUBST([img3tool_requires], [$IMG3TOOL_REQUIRES_STR])
    AC_SUBST(libimg3tool_CFLAGS)
    AC_SUBST(libimg3tool_LIBS)
  else
    echo "*** Note: img3tool has been disabled ***"
  fi
else
  if test "x$with_img3tool" == "xyes"; then
    AC_MSG_ERROR([requested building with img3tool, but library could not be found])
  fi
fi

if test "$debug_build" = true; then
  echo "*** Note: debug build requested ***"
  CFLAGS+=" -g -O0 -DDEBUG=1"
  CXXFLAGS+=" -g -O0 -DDEBUG=1"
fi

if test "$asan_build" = true; then
  echo "*** Note: debug build requested ***"
  CFLAGS+=" -g -O0 -fsanitize=address -fno-omit-frame-pointer -fsanitize-address-use-after-scope"
  CXXFLAGS+=" -g -O0 -fsanitize=address -fno-omit-frame-pointer -fsanitize-address-use-after-scope"
fi


if test "x$with_wtfpwndfu" = "xyes"; then
  AC_DEFINE(WITH_WTFPWNDFU, 1, [Define if you build with wtfpwndfu])
  if test "x$CCARMV6" == "x"; then
    echo "*** Assuming host CC can compile armv6 binaries ***"
    CCARMV6="$CC -arch armv6"
  fi
  echo "*** Using CCARMV6 as $CCARMV6 ***"
  AC_SUBST(CCARMV6)
  if test "x$OTOOLARM" == "x"; then
    echo "*** Assuming host OTOOL can otool arm64/arm32 binaries ***"
    OTOOLARM=$OTOOL
  fi
  echo "*** Using custom OTOOLARM as $OTOOLARM ***"
  AC_SUBST(OTOOLARM)
else
  echo "*** Note: wtfpwndfu has been disabled ***"
fi
AM_CONDITIONAL(WITH_WTFPWNDFU, test x$with_wtfpwndfu == xyes)

# Checks for header files.

if test "x$with_macho" = "xyes"; then
  ORIG_CFLAGS=${CFLAGS}
  CFLAGS+=" -I${lt_sysroot}/include -I${lt_sysroot}/${prefix}/include -I${lt_sysroot}/${ac_default_prefix}/include"
  AC_CHECK_HEADERS([mach-o/loader.h mach-o/nlist.h], [
    AC_DEFINE(HAVE_MACHO_O_HEADER, 1, [Define if you have apple cctools headers])
    AC_SUBST([HAVE_MACHO_O_HEADER], [1])
    have_macho_header=yes;
  ], [
    AC_SUBST([HAVE_MACHO_O_HEADER], [0])
    have_macho_header=no;
  ], [])
  CFLAGS=${ORIG_CFLAGS}

  if test "x$have_macho_header" != "xyes"; then
    AC_MSG_ERROR(["Macho-O headers not found, are apple cctools headers installed?"])
  fi
  with_kernelpatchfinder=yes;
else
  echo "*** Note: wtfpwndfu has been disabled ***"
  with_kernelpatchfinder=no;
fi
AM_CONDITIONAL(WITH_MACHO, test x$with_macho == xyes)
AM_CONDITIONAL(WITH_KERNELPATCHFINDER, test x$with_kernelpatchfinder == xyes)

AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h unistd.h arpa/inet.h winsock.h])

# Check for functions
AC_CHECK_FUNCS([memmem])

LT_INIT

AC_CONFIG_FILES([Makefile
                 include/Makefile
                 libpatchfinder/Makefile
                 libpatchfinder/ibootpatchfinder/Makefile
                 libpatchfinder/kernelpatchfinder/Makefile
                 tools/Makefile
                 tools/binrider/Makefile
                 tools/offsetexporter/Makefile
                 libpatchfinder.pc])
AC_OUTPUT

echo "
Configuration for $PACKAGE-$VERSION:
-------------------------------------------

  install prefix ..........: $prefix
  have img4tool ...........: $with_img4tool
  have img3tool ...........: $with_img3tool
  have mach-o header.......: $with_macho
  debug build  ............: $debug_build
  asan build  .............: $asan_build
  with kernelpatchfinder ..: $with_kernelpatchfinder
  with binrider ...........: $with_binrider
  with offsetexporter .....: $with_offsetexporter
  with wtfpwndfu ..........: $with_wtfpwndfu"

echo "  compiler ................: ${CC}

  Now type 'make' to build $PACKAGE-$VERSION,
  and then 'make install' for installation.
"
