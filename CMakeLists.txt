cmake_minimum_required(VERSION 3.21)

project(XaynxReverseLab
    VERSION 0.1.0
    DESCRIPTION "Static binary analysis and reverse engineering workbench"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(XRL_BUILD_GUI   "Build the Qt 6 desktop application" ON)
option(XRL_BUILD_TESTS "Build the automated test suite" ON)
option(XRL_BUILD_CLI   "Build the command line tool" ON)
option(XRL_WITH_CAPSTONE "Enable disassembly through Capstone (>= 5.0)" ON)
option(XRL_SANITIZE "Build with address/undefined sanitizers (GCC/Clang only)" OFF)

# ---------------------------------------------------------------- warnings
function(xrl_apply_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
        target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wno-sign-conversion)
        if(XRL_SANITIZE)
            target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
            target_link_options(${target} PRIVATE -fsanitize=address,undefined)
        endif()
    endif()
endfunction()

# ---------------------------------------------------------------- Capstone
set(XRL_CAPSTONE_TARGET "")
if(XRL_WITH_CAPSTONE)
    find_package(capstone CONFIG QUIET)
    if(TARGET capstone::capstone)
        set(XRL_CAPSTONE_TARGET capstone::capstone)
    elseif(TARGET capstone)
        set(XRL_CAPSTONE_TARGET capstone)
    else()
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(CAPSTONE QUIET IMPORTED_TARGET capstone)
            if(TARGET PkgConfig::CAPSTONE)
                set(XRL_CAPSTONE_TARGET PkgConfig::CAPSTONE)
            endif()
        endif()
    endif()
    if(XRL_CAPSTONE_TARGET)
        message(STATUS "Capstone: using ${XRL_CAPSTONE_TARGET}")
    else()
        message(WARNING "Capstone not found. Disassembly will be disabled. "
                        "Install Capstone >= 5.0 or configure with -DXRL_WITH_CAPSTONE=OFF.")
    endif()
endif()

# ---------------------------------------------------------------- core library
add_library(xrl_core STATIC
    src/core/sha256.cpp
    src/core/json.cpp
    src/core/util.cpp
    src/formats/detect.cpp
    src/formats/pe.cpp
    src/formats/elf.cpp
    src/formats/macho.cpp
    src/analysis/analyzer.cpp
    src/analysis/heuristics.cpp
    src/analysis/diff.cpp
    src/analysis/entropy.cpp
    src/analysis/strings.cpp
    src/analysis/cfg.cpp
    src/analysis/static_analysis.cpp
    src/analysis/xref.cpp
    src/analysis/workspace.cpp
    src/disassembly/disassembler.cpp
    src/reporting/report.cpp
    src/ghidra/ghidra.cpp)
target_include_directories(xrl_core PUBLIC include)
target_compile_definitions(xrl_core PUBLIC XRL_VERSION="${PROJECT_VERSION}")
xrl_apply_warnings(xrl_core)
if(XRL_CAPSTONE_TARGET)
    target_link_libraries(xrl_core PUBLIC ${XRL_CAPSTONE_TARGET})
    target_compile_definitions(xrl_core PUBLIC XRL_HAS_CAPSTONE=1)
endif()

# Ghidra helper script is shipped next to the binaries and used by the GUI/CLI.
file(COPY ghidra_scripts DESTINATION ${CMAKE_BINARY_DIR})
target_compile_definitions(xrl_core PUBLIC
    XRL_SOURCE_SCRIPT_DIR="${CMAKE_SOURCE_DIR}/ghidra_scripts")

# ---------------------------------------------------------------- CLI
if(XRL_BUILD_CLI)
    add_executable(xrl-cli src/cli/main.cpp)
    target_link_libraries(xrl-cli PRIVATE xrl_core)
    xrl_apply_warnings(xrl-cli)
endif()

# ---------------------------------------------------------------- GUI
if(XRL_BUILD_GUI)
    find_package(Qt6 6.2 QUIET COMPONENTS Widgets Concurrent)
    if(Qt6_FOUND)
        add_subdirectory(src/ui)
    else()
        message(WARNING "Qt 6 not found; the GUI will not be built. "
                        "Set CMAKE_PREFIX_PATH to your Qt installation or use -DXRL_BUILD_GUI=OFF.")
    endif()
endif()

# ---------------------------------------------------------------- tests
if(XRL_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
