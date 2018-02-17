#!/bin/bash

gprefix=`which glibtoolize 2>&1 >/dev/null`
if [ $? -eq 0 ]; then
  glibtoolize --force
else
  libtoolize --force
fi
aclocal -I m4
autoconf
autoheader
automake --add-missing


SUBDIRS="external/libplist"
for SUB in $SUBDIRS; do
    pushd $SUB
    CFLAGS="-arch arm64 -isysroot $(xcrun --show-sdk-path --sdk iphoneos)" CPPFLAGS="-arch arm64 -isysroot $(xcrun --show-sdk-path --sdk iphoneos)" ./autogen.sh --enable-static --disable-shared --host=arm-apple-darwin --without-cython
    popd
done

CFLAGS="-arch arm64 -isysroot $(xcrun --show-sdk-path --sdk iphoneos)" CPPFLAGS="-arch arm64 -isysroot $(xcrun --show-sdk-path --sdk iphoneos)" ./configure --host=arm-apple-darwin --enable-static --disable-shared "$@"
