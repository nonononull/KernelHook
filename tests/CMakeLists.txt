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
