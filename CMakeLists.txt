cmake_minimum_required(VERSION 2.8.12...3.5)
project(SimpleSocket)

option(BUILD_SIMPLE_SOCKET_EXAMPLES "Build the simple socket example projects" ON)

if(BUILD_SIMPLE_SOCKET_EXAMPLES)
    add_subdirectory(examples)
endif()
