cmake_minimum_required(VERSION 2.8)

set(SOURCE_DIR ../../Source)

set(EXE ExampleClient)
project(${EXE})

set(SOURCE_LIST main.cpp)

include_directories(${SOURCE_DIR})

add_executable(${EXE} ${SOURCE_LIST})