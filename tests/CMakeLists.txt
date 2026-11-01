include(FetchContent)
find_package(GTest CONFIG QUIET)
if(NOT GTest_FOUND)
    find_package(GTest QUIET)
endif()
if(NOT TARGET GTest::gtest_main)
    message(STATUS "GoogleTest not installed; fetching v1.15.2 (network required)")
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_Declare(googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz)
    FetchContent_MakeAvailable(googletest)
endif()

add_executable(xrl_tests
    test_util.cpp
    test_json.cpp
    test_formats.cpp
    test_analyzer.cpp
    test_report.cpp
    test_disassembly.cpp
    test_cfg.cpp
    test_static_analysis.cpp
    test_xref.cpp
    test_workspace.cpp
    test_ghidra.cpp
    test_diff.cpp
    test_entropy.cpp
    test_strings.cpp)
target_link_libraries(xrl_tests PRIVATE xrl_core GTest::gtest_main)
xrl_apply_warnings(xrl_tests)

include(GoogleTest)
gtest_discover_tests(xrl_tests DISCOVERY_MODE PRE_TEST)
