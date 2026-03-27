# SPDX-License-Identifier: GPL-2.0-or-later
# CMake toolchain file for cross-compiling KernelHook to ARM64 Linux.
#
# Usage:
#   cmake -DCMAKE_TOOLCHAIN_FILE=cmake/aarch64-linux-gnu.cmake \
#         -DCMAKE_BUILD_TYPE=Debug ..
#
# Prerequisites:
#   - aarch64-linux-gnu-gcc toolchain (apt install gcc-aarch64-linux-gnu)
#   - For running tests: QEMU user-mode (apt install qemu-user)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

# Cross-compiler (override with -DCROSS_COMPILE_PREFIX= if non-standard)
if(NOT DEFINED CROSS_COMPILE_PREFIX)
    set(CROSS_COMPILE_PREFIX aarch64-linux-gnu-)
endif()

set(CMAKE_C_COMPILER   ${CROSS_COMPILE_PREFIX}gcc)
set(CMAKE_CXX_COMPILER ${CROSS_COMPILE_PREFIX}g++)

# Search paths: never search host programs, always search target libs/headers
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Optional sysroot (set via -DCMAKE_SYSROOT=/path/to/sysroot if needed)
