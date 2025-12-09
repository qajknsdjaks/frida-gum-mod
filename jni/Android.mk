LOCAL_PATH := $(call my-dir)

# Prebuilt frida-gum static library
include $(CLEAR_VARS)
LOCAL_MODULE := frida-gum
LOCAL_SRC_FILES := ../libs/libfrida-gum.a
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/../libs
include $(PREBUILT_STATIC_LIBRARY)

# Main shared library (libcpp_shared.so)
include $(CLEAR_VARS)
LOCAL_MODULE := cpp_shared
LOCAL_SRC_FILES := main.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../libs
LOCAL_STATIC_LIBRARIES := frida-gum
LOCAL_LDLIBS := -llog -ldl -lm -lz
LOCAL_CPPFLAGS := -std=c++20 -fvisibility=hidden -O2 -Wall -Wextra -Wno-unused-parameter
LOCAL_LDFLAGS := -Wl,--gc-sections -Wl,--exclude-libs,ALL

include $(BUILD_SHARED_LIBRARY)

