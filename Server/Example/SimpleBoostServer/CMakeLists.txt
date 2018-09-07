cmake_minimum_required(VERSION 2.8)

set(CMAKE_CXX_EXTENSIONS OFF)

set(SOURCE_DIR ../../Source)

set(EXE Example)
project(${EXE})

set(SOURCE_LIST main.cpp)

include_directories(${SOURCE_DIR})

file(COPY settings.ini DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY quatro DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_executable(${EXE} ${SOURCE_LIST})

target_link_libraries(${EXE} elfserver)
