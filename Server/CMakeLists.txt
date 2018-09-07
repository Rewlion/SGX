cmake_minimum_required(VERSION 2.8)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project (Main)

include_directories(Source)

add_subdirectory(Source/ServerV2)
add_subdirectory(Example/SimpleBoostServer)
add_subdirectory(Example/SimpleBoostClient)