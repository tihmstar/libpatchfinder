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

# otherwise img4tool cant find libplist
CFLAGS+=" -I$PWD/external/libplist/include"
CXXFLAGS+=" -I$PWD/external/libplist/include"
export LDFLAGS+=" -L$PWD/external/libplist/src"

MAC="x86_64-apple-darwin$(uname -r)"
IOS="aarch64-apple-darwin"

BUILD="$MAC"
if [ ! -z ${NOCROSS+x} ]; then
  echo "no cross compile"
  HOST="$MAC"
else
  echo "cross compiling for ios"
  HOST="$IOS"
  SYSROOT="$(xcrun --show-sdk-path --sdk iphoneos)"
  CFLAGS+="-arch arm64 -isysroot $SYSROOT"
  CXXFLAGS+="-arch arm64 -isysroot $SYSROOT"
fi

export CFLAGS+="-DIMG4TOOL_NOMAIN"
export CXXFLAGS+="-DIMG4TOOL_NOMAIN"

CONFIGURE_FLAGS="--enable-static --disable-shared\
  --build=$BUILD \
  --host=$HOST \
  --without-cython --without-openssl \
  $@"

SUBDIRS="external/libplist external/img4tool"
for SUB in $SUBDIRS; do
    pushd $SUB
    ./autogen.sh $CONFIGURE_FLAGS
    popd
done

./configure $CONFIGURE_FLAGS

