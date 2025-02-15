#include <kani/simple_socket.hpp>
#include <iostream>

#define DEFAULT_IP                                "localhost"
#define DEFAULT_PORT                          "1234"
#define DEFAULT_PROTOCOL_FAMILY AF_UNSPEC

#define DEFAULT_RECV_MSG_LEN        255

int main(int argc, char* argv[]) {
    using namespace kani::simple_socket;

    SocketInfo info;
    info.m_node                 = DEFAULT_IP;
    info.m_service             = DEFAULT_PORT;
    info.m_protocolFamily = DEFAULT_PROTOCOL_FAMILY;

    UdpServer server(info);

    if (!server.is_valid()) {
        std::cerr << "can't initialized server!" << std::endl;
        return 1;
    }

    if (server.start() != SS_START_RESULT_SUCCESS) {
        std::cerr << "can't start the server!" << std::endl;
        return 1;
    }

    NetAddr client;
    RecvMsg msg(DEFAULT_RECV_MSG_LEN);

    std::cout << "waiting for client message..." << std::endl;

    if (!server.recv_msg(&client, &msg)) {
        std::cerr << "can't received message from client!" << std::endl;
        return 1;
    }

    std::cout << "client ( " << client.get_host() << " : " << client.get_service() << " ) sent message!" << std::endl;
    std::cout << "received message from client: " << msg.m_recvLen << "byte" << std::endl;
    std::cout << "Client: " << msg.m_msg << std::endl;

    SendMsg response;
    response.m_msg = "Hello, client! I'm a server. It's nice :p";

    if (!server.send_msg(&client, &response)) {
        std::cerr << "can't sent message to client!" << std::endl;
        return 1;
    }

    std::cout << "sent message to client: " << response.m_sentLen << "byte" << std::endl;
    std::cout << "Perfect! Now, say to goodbye :')" << std::endl;

    std::cout << "stopping the server..." << std::endl;
    server.stop();

    std::cout << "server stopped" << std::endl;
    return 0;
}