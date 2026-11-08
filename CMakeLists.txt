cmake_minimum_required(VERSION 3.20)
project(CredentialUI VERSION 1.0.0 LANGUAGES C RC)

if(NOT WIN32)
    message(FATAL_ERROR "CredentialUI requires a Windows target.")
endif()

add_executable(CredentialUI WIN32
    src/main.c
    src/credential_environment.c
    src/credential_bundle.c
    bridge/host.c
    bridge/injector.c
    src/credential_ui.c
    src/ui_paint.c
    src/ui_frame.c
    resources/app.rc
)
target_include_directories(CredentialUI PRIVATE include resources bridge)
target_compile_features(CredentialUI PRIVATE c_std_11)
set_target_properties(CredentialUI PROPERTIES C_EXTENSIONS OFF)
target_compile_definitions(CredentialUI PRIVATE
    UNICODE _UNICODE WINVER=0x0601 _WIN32_WINNT=0x0601
)
target_link_libraries(CredentialUI PRIVATE user32 gdi32 comctl32 advapi32 shell32)

if(MSVC)
    target_compile_options(CredentialUI PRIVATE
        $<$<COMPILE_LANGUAGE:C>:/W4>
        $<$<COMPILE_LANGUAGE:C>:/utf-8>
    )
    # The application manifest is already embedded by app.rc.
    target_link_options(CredentialUI PRIVATE /MANIFEST:NO)
    set_property(TARGET CredentialUI PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
elseif(MINGW)
    include(CheckCCompilerFlag)
    check_c_compiler_flag("-mcrtdll=msvcrt-os" CREDENTIAL_UI_HAS_MSVCRT_FLAG)
    if(CREDENTIAL_UI_HAS_MSVCRT_FLAG)
        target_compile_options(CredentialUI PRIVATE $<$<COMPILE_LANGUAGE:C>:-mcrtdll=msvcrt-os>)
        target_link_options(CredentialUI PRIVATE -mcrtdll=msvcrt-os)
    endif()
    target_compile_options(CredentialUI PRIVATE
        $<$<COMPILE_LANGUAGE:C>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wshadow;-finput-charset=UTF-8>
    )
    target_link_options(CredentialUI PRIVATE -municode -static -static-libgcc)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        target_link_options(CredentialUI PRIVATE -s)
    endif()
endif()

install(TARGETS CredentialUI RUNTIME DESTINATION bin)

add_library(CredentialUIBridge SHARED bridge/bridge.c)
target_include_directories(CredentialUIBridge PRIVATE include bridge)
target_compile_features(CredentialUIBridge PRIVATE c_std_11)
target_compile_definitions(CredentialUIBridge PRIVATE
    UNICODE _UNICODE WINVER=0x0601 _WIN32_WINNT=0x0601 SECURITY_WIN32)
if(MSVC)
    target_compile_options(CredentialUIBridge PRIVATE /W4 /utf-8)
    set_property(TARGET CredentialUIBridge PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
elseif(MINGW)
    target_compile_options(CredentialUIBridge PRIVATE -Wall -Wextra -finput-charset=UTF-8)
    target_link_options(CredentialUIBridge PRIVATE -static -static-libgcc)
    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        # GetProcAddress uses the same export names on x86 and x64.
        target_link_options(CredentialUIBridge PRIVATE -Wl,--kill-at)
    endif()
endif()
target_link_libraries(CredentialUIBridge PRIVATE secur32 user32 advapi32 credui)
set_target_properties(CredentialUIBridge PROPERTIES PREFIX "")
if(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 4)
    target_sources(CredentialUIBridge PRIVATE bridge/exports-x86.def)
endif()
# The bridge remains an internal build artifact; only the EXE is installed.
set(embedded_bridge_rc "${CMAKE_CURRENT_BINARY_DIR}/embedded/$<CONFIG>/bridge.rc")
add_custom_command(OUTPUT "${embedded_bridge_rc}"
    COMMAND "${CMAKE_COMMAND}"
        "-DINPUT=$<TARGET_FILE:CredentialUIBridge>"
        "-DOUTPUT=${embedded_bridge_rc}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/scripts/embed_bridge.cmake"
    DEPENDS CredentialUIBridge "${CMAKE_CURRENT_SOURCE_DIR}/scripts/embed_bridge.cmake"
    VERBATIM)
target_sources(CredentialUI PRIVATE "${embedded_bridge_rc}")

include(CTest)
if(BUILD_TESTING)
    add_executable(CredentialUITests tests/integration.c)
    target_include_directories(CredentialUITests PRIVATE include)
    target_compile_definitions(CredentialUITests PRIVATE UNICODE _UNICODE WINVER=0x0601 _WIN32_WINNT=0x0601)
    target_compile_features(CredentialUITests PRIVATE c_std_11)
    target_link_libraries(CredentialUITests PRIVATE user32)
    if(MSVC)
        set_property(TARGET CredentialUITests PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    elseif(MINGW)
        target_link_options(CredentialUITests PRIVATE -municode -static -static-libgcc)
    endif()
    add_test(NAME Protocol COMMAND CredentialUITests)
endif()

if(BUILD_TESTING)
    add_executable(CredentialMetadata tests/credential_metadata.c)
    target_link_libraries(CredentialMetadata PRIVATE advapi32)
    if(MINGW)
        target_link_options(CredentialMetadata PRIVATE -municode -static -static-libgcc)
    elseif(MSVC)
        set_property(TARGET CredentialMetadata PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()
endif()

if(BUILD_TESTING)
    add_executable(CredentialBridgeTests tests/bridge_tests.c)
    target_include_directories(CredentialBridgeTests PRIVATE include bridge)
    target_compile_definitions(CredentialBridgeTests PRIVATE UNICODE _UNICODE SECURITY_WIN32 WINVER=0x0601 _WIN32_WINNT=0x0601)
    target_link_libraries(CredentialBridgeTests PRIVATE secur32 credui advapi32 user32)
    if(MINGW)
        target_link_options(CredentialBridgeTests PRIVATE -municode -static -static-libgcc)
    elseif(MSVC)
        set_property(TARGET CredentialBridgeTests PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()
endif()

if(BUILD_TESTING)
    add_executable(CredentialRuntimeTests tests/runtime.c src/credential_bundle.c
        src/credential_environment.c
        "${embedded_bridge_rc}")
    target_link_libraries(CredentialRuntimeTests PRIVATE advapi32 user32)
    target_include_directories(CredentialRuntimeTests PRIVATE include bridge)
    target_compile_definitions(CredentialRuntimeTests PRIVATE UNICODE _UNICODE WINVER=0x0601 _WIN32_WINNT=0x0601)
    target_compile_features(CredentialRuntimeTests PRIVATE c_std_11)
    if(MINGW)
        target_compile_options(CredentialRuntimeTests PRIVATE -Wall -Wextra -finput-charset=UTF-8)
        target_link_options(CredentialRuntimeTests PRIVATE -municode -static -static-libgcc)
    elseif(MSVC)
        target_compile_options(CredentialRuntimeTests PRIVATE /utf-8)
        set_property(TARGET CredentialRuntimeTests PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()
    add_test(NAME Runtime COMMAND CredentialRuntimeTests $<TARGET_FILE:CredentialUI>)
    add_test(NAME GuiIpc COMMAND CredentialUITests $<TARGET_FILE:CredentialUI>)
    add_test(NAME BridgeIdentity COMMAND CredentialBridgeTests)
    add_executable(CredentialBundleTests tests/bundle.c src/credential_bundle.c)
    target_include_directories(CredentialBundleTests PRIVATE include)
    target_compile_features(CredentialBundleTests PRIVATE c_std_11)
    target_compile_definitions(CredentialBundleTests PRIVATE UNICODE _UNICODE WINVER=0x0601 _WIN32_WINNT=0x0601)
    target_link_libraries(CredentialBundleTests PRIVATE advapi32)
    if(MINGW)
        target_compile_options(CredentialBundleTests PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
        target_link_options(CredentialBundleTests PRIVATE -municode -static -static-libgcc)
    elseif(MSVC)
        set_property(TARGET CredentialBundleTests PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()
    add_test(NAME Bundle COMMAND CredentialBundleTests $<TARGET_FILE:CredentialUI>)
    add_executable(CredentialLogTests tests/logging.c)
    target_include_directories(CredentialLogTests PRIVATE include bridge)
    target_compile_definitions(CredentialLogTests PRIVATE
        UNICODE _UNICODE SECURITY_WIN32 WINVER=0x0601 _WIN32_WINNT=0x0601)
    target_compile_features(CredentialLogTests PRIVATE c_std_11)
    target_link_libraries(CredentialLogTests PRIVATE secur32 credui advapi32 user32)
    if(MINGW)
        target_compile_options(CredentialLogTests PRIVATE -Wall -Wextra -finput-charset=UTF-8)
        target_link_options(CredentialLogTests PRIVATE -municode -static -static-libgcc)
    elseif(MSVC)
        target_compile_options(CredentialLogTests PRIVATE /W4 /utf-8)
        set_property(TARGET CredentialLogTests PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()
    add_test(NAME Logging COMMAND CredentialLogTests
        $<TARGET_FILE:CredentialUI> $<TARGET_FILE:CredentialUIBridge>)
    add_executable(CredentialEnvironmentTests tests/environment.c)
    target_include_directories(CredentialEnvironmentTests PRIVATE include)
    target_compile_features(CredentialEnvironmentTests PRIVATE c_std_11)
    target_compile_definitions(CredentialEnvironmentTests PRIVATE
        UNICODE _UNICODE WINVER=0x0601 _WIN32_WINNT=0x0601)
    if(MINGW)
        target_compile_options(CredentialEnvironmentTests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow -finput-charset=UTF-8)
        target_link_options(CredentialEnvironmentTests PRIVATE -municode -static -static-libgcc)
    elseif(MSVC)
        target_compile_options(CredentialEnvironmentTests PRIVATE /W4 /utf-8)
        set_property(TARGET CredentialEnvironmentTests PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()
    add_test(NAME Environment COMMAND CredentialEnvironmentTests)
endif()
