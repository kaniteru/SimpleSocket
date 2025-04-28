cmake_minimum_required(VERSION 3.10)
project(SimpleSocket LANGUAGES CXX)

add_library(SimpleSocket INTERFACE include/kani/simple_socket.hpp)

target_include_directories(SimpleSocket INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# option
option(BUILD_SIMPLE_SOCKET_EXAMPLES "Build the simple socket example projects" OFF)

if(BUILD_SIMPLE_SOCKET_EXAMPLES)
    add_subdirectory(examples)
endif()
