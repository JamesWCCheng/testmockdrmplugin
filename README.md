# testmockdrmplugin
test mock drm plug
# Get the test code
## switch to /B2G_Nexus5/frameworks/av/media/ 
git clone git@github.com:JamesWCCheng/testmockdrmplugin.git 

# Put the Mock Plugin
Build it first,
./build.sh libmockdrmcryptoplugin

adb push out/target/product/hammerhead/system/lib/libmediaplayerservice.so /system/lib

# Build the exe
##switch to /B2G_Nexus5/
./build.sh testserver
testserver is the module name in Android.mk 

## When build success, put the exe to device or dev-board
adb remount
adb push out/target/product/hammerhead/system/bin/testserver /system/bin

## Execute the exe
adb shell
cd system/bin/
./testserver

You can see the logs on both adb logcat and console.

