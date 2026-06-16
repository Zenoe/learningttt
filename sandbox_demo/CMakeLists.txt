cmake_minimum_required(VERSION 3.25)
project(SandboxDemo VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)


# ---- SandboxBorder.dll (injected Show-in-folder broker, no Qt) ----
add_library(SandboxBorder SHARED
    SandboxBorder/SandboxBorder.cpp
    SandboxBorder/SandboxBorder.h
)
target_compile_definitions(SandboxBorder PRIVATE SANDBOXBORDER_EXPORTS)
target_link_libraries(SandboxBorder PRIVATE shell32)

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
    src/WfpManager.cpp
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
    include/WfpManager.h
    include/NtDefs.h
    driver/include/SandboxIpc.h   # shared with kernel driver
)

add_executable(SandboxDemo WIN32 ${SOURCES} ${HEADERS})

target_include_directories(SandboxDemo PRIVATE
    include
    driver/include          # for SandboxIpc.h
)

target_link_libraries(SandboxDemo PRIVATE
    Qt6::Core
    Qt6::Widgets
    ntdll
    psapi
    advapi32                # SCM / registry APIs used by DriverManager
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
