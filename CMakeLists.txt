# CMakeList.txt : CMake project for AmiBoardInfoTool, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

set(VCPKG_TARGET_TRIPLET "x86-windows-static")
project ("AmiBoardInfoTool")
set(CMAKE_CXX_STANDARD 17)

# vcpkg dependencies
find_library(DISTORMLIB distorm)
find_path(DISTORMH NAMES distorm.h)

# search for alternate name distorm3 used on linux
if (NOT DISTORMLIB OR NOT DISTORMH)
    find_library(DISTORMLIB distorm3)
    find_path(DISTORMH NAMES distorm.h PATH_SUFFIXES distorm3)
endif()

include_directories(${DISTORMH})

add_executable (AmiBoardInfoTool "AmiBoardInfoTool.cpp" "include/peImage.h" "include/baseTypes.h" "include/common.h")
target_link_libraries(AmiBoardInfoTool ${DISTORMLIB})
