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


SYSROOT="$(xcrun --show-sdk-path --sdk iphoneos)"
export CFLAGS+="-arch arm64 -isysroot $SYSROOT -DIMG4TOOL_NOMAIN"
export CXXFLAGS+="-arch arm64 -isysroot $SYSROOT -DIMG4TOOL_NOMAIN"

# otherwise img4tool cant find libplist
CFLAGS+=" -I$PWD/external/libplist/include"
CXXFLAGS+=" -I$PWD/external/libplist/include"
export LDFLAGS+="-L$PWD/external/libplist/src"

CONFIGURE_FLAGS="--enable-static --disable-shared\
  --build=x86_64-apple-darwin`uname -r` \
  --host=aarch64-apple-darwin \
  --without-cython --without-openssl \
  --without-lzfse \
  $@"

SUBDIRS="external/libplist external/img4tool"
for SUB in $SUBDIRS; do
    pushd $SUB
    ./autogen.sh $CONFIGURE_FLAGS
    popd
done

./configure $CONFIGURE_FLAGS

