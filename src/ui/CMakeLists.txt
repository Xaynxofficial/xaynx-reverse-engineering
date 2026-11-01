find_package(Qt6 6.2 REQUIRED COMPONENTS Widgets Concurrent)

set(CMAKE_AUTOMOC ON)

qt_add_executable(xaynx-reverse-lab MACOSX_BUNDLE WIN32
    main.cpp
    MainWindow.cpp
    MainWindow.hpp
    WorkspaceWidget.cpp
    WorkspaceWidget.hpp
    CfgGraphView.cpp
    CfgGraphView.hpp
    XrefGraphView.cpp
    XrefGraphView.hpp
    HexView.cpp
    HexView.hpp
    EntropyHeatmap.cpp
    EntropyHeatmap.hpp
    StringsTable.cpp
    StringsTable.hpp
    GhidraRunner.cpp
    GhidraRunner.hpp
    Theme.cpp
    Theme.hpp
    TableWidgets.hpp
    UiUtil.hpp)

target_link_libraries(xaynx-reverse-lab PRIVATE Qt6::Widgets Qt6::Concurrent xrl_core)
xrl_apply_warnings(xaynx-reverse-lab)

set_target_properties(xaynx-reverse-lab PROPERTIES
    MACOSX_BUNDLE_BUNDLE_NAME "Xaynx Reverse Lab"
    MACOSX_BUNDLE_GUI_IDENTIFIER "dev.xaynx.reverselab"
    MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
    OUTPUT_NAME "Xaynx Reverse Lab")

# Ship the Ghidra helper script with the application so the optional integration can find it.
if(APPLE)
    add_custom_command(TARGET xaynx-reverse-lab POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_SOURCE_DIR}/ghidra_scripts
            "$<TARGET_BUNDLE_CONTENT_DIR:xaynx-reverse-lab>/Resources/ghidra_scripts")
else()
    add_custom_command(TARGET xaynx-reverse-lab POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_SOURCE_DIR}/ghidra_scripts
            "$<TARGET_FILE_DIR:xaynx-reverse-lab>/ghidra_scripts")
endif()

# ---- install / packaging (see docs/packaging.md)
include(GNUInstallDirs)
if(APPLE)
    install(TARGETS xaynx-reverse-lab BUNDLE DESTINATION .)
elseif(WIN32)
    install(TARGETS xaynx-reverse-lab RUNTIME DESTINATION .)
    install(DIRECTORY ${CMAKE_SOURCE_DIR}/ghidra_scripts DESTINATION .)
else()
    install(TARGETS xaynx-reverse-lab RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(DIRECTORY ${CMAKE_SOURCE_DIR}/ghidra_scripts DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
install(FILES ${CMAKE_SOURCE_DIR}/LICENSE ${CMAKE_SOURCE_DIR}/README.md DESTINATION
    $<IF:$<BOOL:${APPLE}>,.,${CMAKE_INSTALL_DOCDIR}>)
