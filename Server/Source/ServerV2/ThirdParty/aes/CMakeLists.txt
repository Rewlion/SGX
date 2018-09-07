cmake_minimum_required(VERSION 2.8)

set(CMAKE_CXX_EXTENSIONS OFF)

project(aes)

set(SOURCE_LIST aes.cpp
                aes.h)

add_library(aes STATIC ${SOURCE_LIST})