cmake_minimum_required(VERSION 3.21)

if(POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
endif()

project(SandboxDemoHookWin32 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(ROOT_DIR "${CMAKE_CURRENT_LIST_DIR}/..")
set(MAIN_DEBUG_DIR "${ROOT_DIR}/out/build/debug" CACHE PATH "Directory containing SandboxDemo.exe and HookDll.dll")

set(DETOURS_X86_ROOT "C:/vcpkg/installed/x86-windows" CACHE PATH "vcpkg detours x86 triplet root")
if(NOT EXISTS "${DETOURS_X86_ROOT}/include/detours/detours.h")
    message(FATAL_ERROR "detours.h not found under ${DETOURS_X86_ROOT}. Install with: vcpkg install detours:x86-windows")
endif()

add_library(HookDll32 SHARED
    "${ROOT_DIR}/hookdll/dllmain.cpp"
    "${ROOT_DIR}/hookdll/Hooks.cpp"
    "${ROOT_DIR}/hookdll/Hooks.h"
    "${ROOT_DIR}/hookdll/HookLogger.cpp"
    "${ROOT_DIR}/hookdll/HookLogger.h"
    "${ROOT_DIR}/hookdll/PipeClient.cpp"
    "${ROOT_DIR}/hookdll/PipeClient.h"
    HookDll32.def
    "${ROOT_DIR}/shared/HookIpcProtocol.h"
)

add_executable(HookDllInjector32 WIN32
    HookDllInjector32.cpp
)

target_include_directories(HookDll32 PRIVATE
    "${ROOT_DIR}/hookdll"
    "${ROOT_DIR}/shared"
    "${DETOURS_X86_ROOT}/include"
)

target_link_libraries(HookDll32 PRIVATE
    "$<$<CONFIG:Debug>:${DETOURS_X86_ROOT}/debug/lib/detours.lib>"
    "$<$<NOT:$<CONFIG:Debug>>:${DETOURS_X86_ROOT}/lib/detours.lib>"
    shell32
    ole32
    user32
    advapi32
)

target_link_libraries(HookDllInjector32 PRIVATE shell32)

target_compile_definitions(HookDll32 PRIVATE
    UNICODE
    _UNICODE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

target_compile_definitions(HookDllInjector32 PRIVATE
    UNICODE
    _UNICODE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

target_compile_options(HookDll32 PRIVATE /W3 /wd4996 /utf-8)
target_compile_options(HookDllInjector32 PRIVATE /W3 /utf-8)

set_target_properties(HookDll32 HookDllInjector32 PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${MAIN_DEBUG_DIR}"
    LIBRARY_OUTPUT_DIRECTORY_DEBUG "${MAIN_DEBUG_DIR}"
    ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/Debug"
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)
