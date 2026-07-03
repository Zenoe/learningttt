cmake_minimum_required(VERSION 3.25)
project(SandboxDemo VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOUIC_SEARCH_PATHS
    ${CMAKE_CURRENT_SOURCE_DIR}/ui
)

set(DETOURS_ROOT "C:/vcpkg/installed/x64-windows" CACHE PATH "Microsoft Detours install root")
find_path(DETOURS_INCLUDE_DIR
    NAMES detours/detours.h detours.h
    PATHS
        "${DETOURS_ROOT}/include"
        "$ENV{VCPKG_ROOT}/installed/x64-windows/include"
        "C:/vcpkg/installed/x64-windows/include"
)
find_library(DETOURS_LIBRARY
    NAMES detours
    PATHS
        "${DETOURS_ROOT}/lib"
        "$ENV{VCPKG_ROOT}/installed/x64-windows/lib"
        "C:/vcpkg/installed/x64-windows/lib"
)
if (NOT DETOURS_INCLUDE_DIR OR NOT DETOURS_LIBRARY)
    message(FATAL_ERROR "Microsoft Detours not found")
endif()


#set_target_properties(SandboxBorder PROPERTIES
#    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
#)

# Qt6 — set CMAKE_PREFIX_PATH to your Qt installation, e.g.:
#   cmake -DCMAKE_PREFIX_PATH="C:/Qt/6.10.0/msvc2022_64" ..
find_package(Qt6 REQUIRED COMPONENTS Core Widgets)

add_library(HookDll SHARED
    hookdll/dllmain.cpp
    hookdll/Hooks.cpp
    hookdll/Hooks.h
    hookdll/HookLogger.cpp
    hookdll/HookLogger.h
    hookdll/PipeClient.cpp
    hookdll/PipeClient.h
    hookdll/HookDll.def
    shared/HookIpcProtocol.h
)

target_include_directories(HookDll PRIVATE
    hookdll
    shared
    ${DETOURS_INCLUDE_DIR}
)

target_link_libraries(HookDll PRIVATE
    ${DETOURS_LIBRARY}
    shell32
    ole32
    user32
)

target_compile_options(HookDll PRIVATE /W3 /wd4996)
set_target_properties(HookDll PROPERTIES
    OUTPUT_NAME "HookDll"
    PREFIX ""
    # HookDll is injected into Chrome, whose DLL search path is unrelated to
    # SandboxDemo.exe. Keep the CRT inside HookDll so Debug builds do not rely
    # on MSVCP140D/VCRUNTIME140D/ucrtbased being discoverable by Chrome.
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

set(SOURCES
    src/main.cpp
    src/MainWindow.cpp
    src/DetourProcessLauncher.cpp
    src/HookIpcServer.cpp
    src/SandboxFileExplorer.cpp
    src/SandboxEngine.cpp
    src/ProcessMonitor.cpp
    src/DriverManager.cpp
    src/StringUtil.cpp
    ui/SandboxFileExplorer.ui
)

set(HEADERS
    include/MainWindow.h
    include/DetourProcessLauncher.h
    include/HookIpcServer.h
    include/SandboxFileExplorer.h
    include/SandboxEngine.h
    include/ProcessMonitor.h
    include/DriverManager.h
    include/NtDefs.h
    driver/include/SandboxIpc.h   # shared with kernel driver
)

add_executable(SandboxDemo WIN32 ${SOURCES} ${HEADERS})
add_dependencies(SandboxDemo HookDll)

target_include_directories(SandboxDemo PRIVATE
    include
    shared
    driver/include          # for SandboxIpc.h
    ${DETOURS_INCLUDE_DIR}
)

target_link_libraries(SandboxDemo PRIVATE
    Qt6::Core
    Qt6::Widgets
    ntdll
    psapi
    advapi32                # SCM / registry APIs used by DriverManager
    ole32
    oleaut32
    shlwapi
    ${DETOURS_LIBRARY}
)

target_compile_options(SandboxDemo PRIVATE /W3 /wd4996 /EHsc)

add_custom_command(TARGET SandboxDemo POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:HookDll>
            $<TARGET_FILE_DIR:SandboxDemo>
    COMMENT "Copying HookDll.dll next to SandboxDemo.exe"
)

# Copy next to the main EXE automatically after build
#add_dependencies(SandboxDemo SandboxBorder)

# ---- Kernel driver is built separately with WDK ----
# See driver/CMakeLists.txt and driver/SandboxFlt.inf
# Build instructions in BUILD.md
message(STATUS "")
message(STATUS "Qt app: SandboxDemo configured.")
message(STATUS "Kernel driver: build separately — see driver/CMakeLists.txt")
message(STATUS "")
