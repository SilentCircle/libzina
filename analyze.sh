#!/bin/sh

if test -n "$(which clang-5.0)"; then
  CC=clang-5.0 CXX=clang++-5.0 SCAN=scan-build-5.0
elif test -n "$(which clang-4.0)"; then
  CC=clang-4.0 CXX=clang++-4.0 SCAN=scan-build-4.0
elif test -n "$(which clang-3.9)"; then
  CC=clang-3.9 CXX=clang++-3.9 SCAN=scan-build-3.9
elif test -n "$(which clang-3.8)"; then
  CC=clang-3.8 CXX=clang++-3.8 SCAN=scan-build-3.8
elif test -n "$(which clang)"; then
  CC=clang CXX=clang++ SCAN=scan-build
else
  echo "!! Error: not able to find Clang compiler">&2
  exit 1
fi
if test -z "$(which $CXX)"; then
  echo "!! Error: not able to find $CXX">&2
  exit 1
fi
if test -z "$(which $SCAN)"; then
  echo "!! Error: not able to find $SCAN">&2
  exit 1
fi

export CC
export CXX

$SCAN -v -v \
  --use-cc="$(which $CC)" \
  --use-c++="$(which $CXX)" \
  cmake -DCMAKE_BUILD_TYPE=Debug .

$SCAN -v -v \
  --use-cc="$(which $CC)" \
  --use-c++="$(which $CXX)" \
  make -j
