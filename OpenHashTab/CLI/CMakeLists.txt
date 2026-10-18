# SPDX-License-Identifier: GPL-3.0-or-later
set(APP "${CMAKE_CURRENT_SOURCE_DIR}/../OpenHashTab")
add_executable(OpenHashTabCLI Main.cpp ${APP}/BatchOperations.cpp ${APP}/Report.cpp
    ${APP}/SumFileParser.cpp ${APP}/utl.cpp ${APP}/base64.cpp ${APP}/Settings.cpp)
target_include_directories(OpenHashTabCLI PRIVATE ${APP})
target_precompile_headers(OpenHashTabCLI PRIVATE ${APP}/stdafx.h)
if(CMAKE_DISABLE_PRECOMPILE_HEADERS)
    target_compile_options(OpenHashTabCLI PRIVATE "/FI${APP}/stdafx.h")
endif()
target_compile_options(OpenHashTabCLI PRIVATE /EHsc)
target_compile_definitions(OpenHashTabCLI PRIVATE UNICODE _UNICODE "CI_VERSION=\"${CI_VERSION}\"")
target_link_libraries(OpenHashTabCLI PRIVATE LegacyAlgorithms AlgorithmsDlls ctre
    ntdll comctl32 shlwapi comdlg32 shell32 ole32 uuid)
add_custom_command(TARGET OpenHashTabCLI POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_RUNTIME_DLLS:OpenHashTabCLI> $<TARGET_FILE_DIR:OpenHashTabCLI>
    COMMAND_EXPAND_LISTS)
