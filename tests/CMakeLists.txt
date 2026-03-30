# SPDX-License-Identifier: GPL-2.0-or-later
# KernelHook userspace test suite

# Helper: define a test executable linked against libkernelhook
function(kh_add_test name source)
    add_executable(${name} ${source})
    target_include_directories(${name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include/arch/arm64
    )
    target_compile_definitions(${name} PRIVATE __USERSPACE__)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Werror -Wno-unused-parameter)
    target_link_libraries(${name} PRIVATE kernelhook)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

# --- Test executables ---
kh_add_test(test_framework_smoke test_framework_smoke.c)
kh_add_test(test_hmem test_hmem.c)
kh_add_test(test_reloc test_reloc.c)
kh_add_test(test_chain test_chain.c)
kh_add_test(test_hook_basic test_hook_basic.c)
kh_add_test(test_hook_chain test_hook_chain.c)
kh_add_test(test_stress test_stress.c)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(test_stress PRIVATE pthread)
endif()

kh_add_test(test_remote test_remote.c)
kh_add_test(test_pac_strip test_pac_strip.c)
kh_add_test(test_interaction test_interaction.c)
kh_add_test(test_unit test_unit.c)

# --- Security integration tests with -mbranch-protection=standard ---
include(CheckCCompilerFlag)
check_c_compiler_flag(-mbranch-protection=standard HAS_BRANCH_PROTECTION)

kh_add_test(test_security test_security.c)
if(HAS_BRANCH_PROTECTION)
    target_compile_options(test_security PRIVATE -mbranch-protection=standard)
    target_compile_definitions(test_security PRIVATE HAS_BRANCH_PROTECTION)
endif()

# --- ARM64 Linux-specific tests ---
# These tests verify Linux-specific functionality (mprotect W^X, SCS with X18,
# kCFI).  On non-Linux platforms, all tests skip gracefully via SKIP_TEST().
kh_add_test(test_linux_arm64 test_linux_arm64.c)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # On Linux, enable BTI+PAC for the SCS interaction targets if supported
    if(HAS_BRANCH_PROTECTION)
        target_compile_options(test_linux_arm64 PRIVATE -mbranch-protection=standard)
        target_compile_definitions(test_linux_arm64 PRIVATE HAS_BRANCH_PROTECTION)
    endif()
endif()

# --- Coverage gap tests ---
kh_add_test(test_error_paths test_error_paths.c)
kh_add_test(test_typed_wrappers test_typed_wrappers.c)
kh_add_test(test_fp_edge test_fp_edge.c)
