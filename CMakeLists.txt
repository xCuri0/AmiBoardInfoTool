# CMakeList.txt : CMake project for AmiBoardInfoTool, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

set(CMAKE_TOOLCHAIN_FILE "C:/Users/chungus/Documents/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")

project ("AmiBoardInfoTool")


set(CMAKE_CXX_STANDARD 17)

# vcpkg dependencies
find_library(DISTORMLIB distorm)
find_path(DISTORMH NAMES distorm.h)

include_directories(${DISTORMH})

add_executable (AmiBoardInfoTool "AmiBoardInfoTool.cpp" "include/peImage.h" "include/baseTypes.h" "include/common.h")
target_link_libraries(AmiBoardInfoTool ${DISTORMLIB})
