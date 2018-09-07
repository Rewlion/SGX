cmake_minimum_required(VERSION 2.8)

set(CMAKE_CXX_EXTENSIONS OFF)

project(inih)

set(SOURCE_LIST cpp/INIReader.cpp
                cpp/INIReader.h
                ini.c)

add_library(inih STATIC ${SOURCE_LIST})