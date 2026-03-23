# SPDX-License-Identifier: GPL-2.0-or-later
# KernelHook userspace build — does NOT replace the kernel Makefile.
cmake_minimum_required(VERSION 3.16)
project(KernelHook C)

# --- Architecture check ---
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
    set(ARCH_ARM64 TRUE)
else()
    message(FATAL_ERROR "Unsupported architecture: ${CMAKE_SYSTEM_PROCESSOR}. Only ARM64 is supported.")
endif()

# --- Platform detection ---
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(PLATFORM_SOURCE src/platform/linux.c)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(PLATFORM_SOURCE src/platform/darwin.c)
else()
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}. Only Linux and macOS are supported.")
endif()

# --- Library sources ---
set(LIB_SOURCES
    src/hmem.c
    src/arch/arm64/inline.c
    src/arch/arm64/insn.c
    src/arch/arm64/transit.c
    ${PLATFORM_SOURCE}
    src/platform/hook_mem_user.c
    src/platform/hook_install_user.c
    src/platform/log_user.c
    src/core_user.c
)

add_library(kernelhook STATIC ${LIB_SOURCES})

target_include_directories(kernelhook PUBLIC
    include
    include/arch/arm64
)

target_compile_definitions(kernelhook PUBLIC __USERSPACE__)

target_compile_options(kernelhook PRIVATE
    -Wall -Wextra -Werror
    -Wno-unused-parameter
)

# --- Build type flags ---
set(CMAKE_C_FLAGS_DEBUG "-O0 -g -fsanitize=address" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG" CACHE STRING "" FORCE)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_link_options(kernelhook PUBLIC -fsanitize=address)
endif()

# --- Tests (if present) ---
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt)
    enable_testing()
    add_subdirectory(tests)
endif()
