cmake_minimum_required(VERSION 3.28.1)
project(examples)

set(CMAKE_CXX_STANDARD 98)

function(add_example_project name src)
    add_executable(${name} "${src}")
    target_include_directories(${name} PRIVATE "${CMAKE_SOURCE_DIR}/include")

    if (WIN32)
        target_link_libraries(${name} PRIVATE Ws2_32 Mswsock AdvApi32)
    endif()
endfunction()

add_example_project(SimpleTcpServer "simple_tcp_server.cpp")
add_example_project(SimpleTcpClient "simple_tcp_client.cpp")

add_example_project(SimpleUdpServer "simple_udp_server.cpp")
add_example_project(SimpleUdpClient "simple_udp_client.cpp")