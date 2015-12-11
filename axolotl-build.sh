#!/bin/bash

if [ ! -d "${WORKSPACE}/silentphone2" ]; then
    echo '***** Variable WORKSPACE does not point to correct directory *****'
    exit 1
fi

if [ "x$ANDROID_NDK" = "x" ]; then
    echo '***** Variable ANDROID_NDK not set *****'
    exit 1
fi

if [[ "$SC_BUILD_TYPE" = "DEVELOP" ]];
then
    BUILD_TYPE=Debug
    echo "*** building develop configuration"
else
   BUILD_TYPE="Release"
   echo "*** building release configuration"
fi

rm -rf buildAxoAndroid
mkdir buildAxoAndroid
cd buildAxoAndroid

echo "Building on directory $WORKSPACE"
cmake -DANDROID=ON -DCMAKE_BUILD_TYPE=$BUILD_TYPE ..

if make android; then
    echo "Android build OK"
else
    exit 1
fi

# now copy the created static libs to silentphone2 JNI directory
cp android/obj/local/armeabi-v7a/libaxolotl++.a ${WORKSPACE}/silentphone2/jni/armeabi-v7a/
cp protobuf/android/obj/local/armeabi-v7a/libprotobuf-cpp-lite.a ${WORKSPACE}/silentphone2/jni/armeabi-v7a/

# cleanup build directory
rm -rf buildAxoAndroid
exit 0
