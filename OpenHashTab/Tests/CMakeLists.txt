# SPDX-License-Identifier: GPL-3.0-or-later
set(APP "${CMAKE_CURRENT_SOURCE_DIR}/../OpenHashTab")
add_executable(CoreTests ../../tests/CoreTests.cpp ../../tests/DialogTemplates.rc
    ${APP}/base64.cpp ${APP}/utl.cpp ${APP}/SumFileParser.cpp ${APP}/path.cpp
    ${APP}/Settings.cpp ${APP}/Coordinator.cpp ${APP}/FileHashTask.cpp
    ${APP}/Queues.cpp ${APP}/Exporter.cpp)
target_include_directories(CoreTests PRIVATE ${APP})
target_precompile_headers(CoreTests PRIVATE ${APP}/stdafx.h)
if(CMAKE_DISABLE_PRECOMPILE_HEADERS)
    target_compile_options(CoreTests PRIVATE "/FI${APP}/stdafx.h")
endif()
target_compile_definitions(CoreTests PRIVATE UNICODE _UNICODE "CI_VERSION=\"${CI_VERSION}\"")
target_compile_options(CoreTests PRIVATE /EHsc)
target_link_libraries(CoreTests PRIVATE LegacyAlgorithms AlgorithmsDlls ctre concurrentqueue tiny-json
    ntdll winhttp comctl32 shlwapi comdlg32 shell32 ole32 uuid)
add_executable(EncodingTests ../../tests/EncodingTests.cpp ${APP}/base64.cpp)
target_include_directories(EncodingTests PRIVATE ${APP})
target_compile_options(EncodingTests PRIVATE /EHsc)
add_test(NAME core COMMAND CoreTests)
add_test(NAME encoding COMMAND EncodingTests)
set_tests_properties(core encoding PROPERTIES TIMEOUT 180)
add_custom_command(TARGET CoreTests POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_RUNTIME_DLLS:CoreTests> $<TARGET_FILE_DIR:CoreTests>
    COMMAND_EXPAND_LISTS)
add_executable(ShellTests ../../tests/ShellTests.cpp)
target_compile_definitions(ShellTests PRIVATE UNICODE _UNICODE)
target_link_libraries(ShellTests PRIVATE ole32 shell32 comctl32 uuid)
add_test(NAME load-extension COMMAND ShellTests --load-only $<TARGET_FILE:OpenHashTab>)
set_tests_properties(load-extension PROPERTIES TIMEOUT 30)

set_target_properties(CoreTests EncodingTests ShellTests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Tests")
