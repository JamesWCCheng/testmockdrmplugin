LOCAL_PATH:= $(call my-dir)

ifneq ($(BOARD_USE_CUSTOM_MEDIASERVEREXTENSIONS),true)
include $(CLEAR_VARS)
LOCAL_SRC_FILES := register.cpp
LOCAL_MODULE := libregistermsexttest
LOCAL_MODULE_TAGS := optional
include $(BUILD_STATIC_LIBRARY)
endif

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	main_testserver.cpp 

LOCAL_SHARED_LIBRARIES := \
	libaudioflinger \
	libaudiopolicyservice \
	libcamera_metadata\
	libcameraservice \
	libmedialogservice \
	libcutils \
	libnbaio \
	libmedia \
	libmediaplayerservice \
	libutils \
	liblog \
	libbinder \
	libsoundtriggerservice

LOCAL_STATIC_LIBRARIES := \
	libregistermsexttest

LOCAL_C_INCLUDES := \
    frameworks/av/media/libmediaplayerservice \
    frameworks/av/services/medialog \
    frameworks/av/services/audioflinger \
    frameworks/av/services/audiopolicy \
    frameworks/av/services/camera/libcameraservice \
    $(call include-path-for, audio-utils) \
    frameworks/av/services/soundtrigger \
    $(TOP)/frameworks/native/include/media

LOCAL_MODULE:= testserver
LOCAL_32_BIT_ONLY := true
include external/stlport/libstlport.mk
include $(BUILD_EXECUTABLE)
