cmake_minimum_required(VERSION 3.25)
project(SandboxDemo VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

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
    message(FATAL_ERROR "Microsoft Detours is required for SandboxBorder.dll")
endif()

# ---- SandboxBorder.dll (injected Show-in-folder broker, no Qt) ----
add_library(SandboxBorder SHARED
    SandboxBorder/SandboxBorder.cpp
    SandboxBorder/SandboxBorder.h
    SandboxBorder/SandboxBorder.def
)
target_compile_definitions(SandboxBorder PRIVATE SANDBOXBORDER_EXPORTS)
target_include_directories(SandboxBorder PRIVATE ${DETOURS_INCLUDE_DIR})
target_link_libraries(SandboxBorder PRIVATE shell32 ${DETOURS_LIBRARY})

#set_target_properties(SandboxBorder PROPERTIES
#    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
#)

# Qt6 — set CMAKE_PREFIX_PATH to your Qt installation, e.g.:
#   cmake -DCMAKE_PREFIX_PATH="C:/Qt/6.10.0/msvc2022_64" ..
find_package(Qt6 REQUIRED COMPONENTS Core Widgets)

set(SOURCES
    src/main.cpp
    src/MainWindow.cpp
    src/SandboxEngine.cpp
    src/ProcessMonitor.cpp
    src/DriverManager.cpp
    src/VaultManager.cpp
    src/SandboxExplorer.cpp
    src/SandboxEngine_Inject.cpp
    src/StringUtil.cpp
)

set(HEADERS
    include/MainWindow.h
    include/SandboxEngine.h
    include/SandboxExplorer.h
    include/ProcessMonitor.h
    include/DriverManager.h
    include/VaultManager.h
    include/NtDefs.h
    driver/include/SandboxIpc.h   # shared with kernel driver
)

add_executable(SandboxDemo WIN32 ${SOURCES} ${HEADERS})

target_include_directories(SandboxDemo PRIVATE
    include
    driver/include          # for SandboxIpc.h
    ${DETOURS_INCLUDE_DIR}
)

target_link_libraries(SandboxDemo PRIVATE
    Qt6::Core
    Qt6::Widgets
    ntdll
    psapi
    advapi32                # SCM / registry APIs used by DriverManager
    virtdisk
    bcrypt
    ${DETOURS_LIBRARY}
)

target_compile_options(SandboxDemo PRIVATE /W3 /wd4996)

# Copy next to the main EXE automatically after build
add_dependencies(SandboxDemo SandboxBorder)

# ---- Kernel driver is built separately with WDK ----
# See driver/CMakeLists.txt and driver/SandboxFlt.inf
# Build instructions in BUILD.md
message(STATUS "")
message(STATUS "Qt app: SandboxDemo configured.")
message(STATUS "Kernel driver: build separately — see driver/CMakeLists.txt")
message(STATUS "")
