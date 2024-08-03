#include <simple_socket.hpp>
#include <iostream>

#define DEFAULT_IP                                      "localhost"
#define DEFAULT_PORT                                "1234"
#define DEFAULT_PROTOCOL_FAMILY     AF_UNSPEC
#define DEFAULT_BACKLOG                         SOMAXCONN

#define DEFAULT_RECV_MSG_LEN             255

int main(int argc, char* argv[]) {
    kani::TcpServerSocketInfo info;
    info.m_node = DEFAULT_IP;
    info.m_service = DEFAULT_PORT;
    info.m_protocolFamily = DEFAULT_PROTOCOL_FAMILY;
    info.m_backlog = DEFAULT_BACKLOG;

    kani::TcpServer server(info);

    if (!server.is_valid()) {
        std::cerr << "can't initialized server!" << std::endl;
        return 1;
    }

    if (server.start() != kani::SS_START_RESULT_SUCCESS) {
        std::cerr << "can't start the server!" << std::endl;
        return 1;
    }

    kani::TcpNetClient client;
    std::cout << "waiting for client..." << std::endl;

    while (!server.wait_client(&client)) { }

    std::cout << "client ( " << client.get_ip() << " : " << client.get_port() << " ) connected!" << std::endl;

    kani::SendMsg msg;
    msg.m_msg = "Hello, client! I'm a server. Welcome to my simple server 8)";

    if (!server.send_msg(&client, &msg)) {
        std::cerr << "can't sent message to client!" << std::endl;
        return 1;
    }

    std::cout << "sent message to client: " << msg.m_sentLen << "byte" << std::endl;

    kani::RecvMsg response(DEFAULT_RECV_MSG_LEN);

    if (!server.recv_msg(&client, &response)) {
        std::cerr << "can't received message from client!" << std::endl;
        return 1;
    }

    std::cout << "received message from client: " << response.m_recvLen << "byte" << std::endl;
    std::cout << "Client: " << response.m_msg << std::endl;

    std::cout << "Perfect! Now, say to goodbye :')" << std::endl;
    client.disconnect();

    std::cout << "stopping the server..." << std::endl;
    server.stop();

    std::cout << "server stopped" << std::endl;
    return 0;
}