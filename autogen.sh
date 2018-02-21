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


SUBDIRS="external/libplist external/img4tool"
export CFLAGS="-arch arm64 -isysroot $(xcrun --show-sdk-path --sdk iphoneos) -D IMG4TOOL_NOMAIN -D IMG4TOOL_NOOPENSSL"
export CPPFLAGS="-arch arm64 -isysroot $(xcrun --show-sdk-path --sdk iphoneos)"
for SUB in $SUBDIRS; do
    pushd $SUB
    ./autogen.sh --enable-static --disable-shared --host=arm-apple-darwin --without-cython
    popd
done

./configure --host=arm-apple-darwin --enable-static --disable-shared "$@"
