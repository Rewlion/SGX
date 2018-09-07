cmake_minimum_required(VERSION 2.8)

set(CMAKE_CXX_EXTENSIONS OFF)

set(SOURCE_DIR ../)
set(INIH_DIR ThirdParty/inih)
set(AES_DIR ThirdParty/aes)

project(elfserver)

set(SOURCE_LIST elfserver.cpp
                elfserver.h
		crypto.cpp
		crypto.h
		utils.hpp)

include_directories(${SOURCE_DIR})

add_subdirectory(${INIH_DIR})
add_subdirectory(${AES_DIR})

add_library(elfserver STATIC ${SOURCE_LIST})

target_link_libraries(elfserver inih aes)
