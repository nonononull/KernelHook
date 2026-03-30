# SPDX-License-Identifier: GPL-2.0-or-later
# CMake wrapper that auto-detects the Android NDK and delegates to its
# official toolchain file for ARM64 cross-compilation.
#
# Usage:
#   cmake -B build_android \
#         -DCMAKE_TOOLCHAIN_FILE=cmake/android-arm64.cmake \
#         -DCMAKE_BUILD_TYPE=Debug
#
# NDK search order:
#   1. ANDROID_NDK_HOME env var
#   2. ANDROID_HOME/ndk/<highest-version>/
#   3. ANDROID_SDK_ROOT/ndk/<highest-version>/

# --- Locate NDK ---

if(DEFINED ENV{ANDROID_NDK_HOME} AND EXISTS "$ENV{ANDROID_NDK_HOME}")
    set(_NDK_ROOT "$ENV{ANDROID_NDK_HOME}")
elseif(DEFINED ENV{ANDROID_HOME} AND EXISTS "$ENV{ANDROID_HOME}/ndk")
    # Pick highest version directory (filter out non-directories like .zip files)
    file(GLOB _NDK_VERSIONS LIST_DIRECTORIES true "$ENV{ANDROID_HOME}/ndk/*")
    list(FILTER _NDK_VERSIONS EXCLUDE REGEX "\\.(zip|tar|gz)$")
    if(_NDK_VERSIONS)
        list(SORT _NDK_VERSIONS COMPARE NATURAL ORDER DESCENDING)
        list(GET _NDK_VERSIONS 0 _NDK_ROOT)
    endif()
elseif(DEFINED ENV{ANDROID_SDK_ROOT} AND EXISTS "$ENV{ANDROID_SDK_ROOT}/ndk")
    file(GLOB _NDK_VERSIONS LIST_DIRECTORIES true "$ENV{ANDROID_SDK_ROOT}/ndk/*")
    list(FILTER _NDK_VERSIONS EXCLUDE REGEX "\\.(zip|tar|gz)$")
    if(_NDK_VERSIONS)
        list(SORT _NDK_VERSIONS COMPARE NATURAL ORDER DESCENDING)
        list(GET _NDK_VERSIONS 0 _NDK_ROOT)
    endif()
endif()

if(NOT DEFINED _NDK_ROOT OR NOT EXISTS "${_NDK_ROOT}")
    message(FATAL_ERROR
        "Android NDK not found. Searched:\n"
        "  1. ANDROID_NDK_HOME=$ENV{ANDROID_NDK_HOME}\n"
        "  2. ANDROID_HOME=$ENV{ANDROID_HOME}/ndk/<version>\n"
        "  3. ANDROID_SDK_ROOT=$ENV{ANDROID_SDK_ROOT}/ndk/<version>\n"
        "\n"
        "Set ANDROID_NDK_HOME to the NDK root directory.")
endif()

# --- Delegate to official NDK toolchain ---

set(_NDK_TOOLCHAIN "${_NDK_ROOT}/build/cmake/android.toolchain.cmake")
if(NOT EXISTS "${_NDK_TOOLCHAIN}")
    message(FATAL_ERROR "NDK toolchain not found at: ${_NDK_TOOLCHAIN}")
endif()

set(ANDROID_ABI "arm64-v8a" CACHE STRING "")
set(ANDROID_PLATFORM "android-28" CACHE STRING "")
set(ANDROID_STL "none" CACHE STRING "")

include("${_NDK_TOOLCHAIN}")
