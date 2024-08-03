#include <simple_socket.hpp>
#include <iostream>

#define DEFAULT_IP                                      "localhost"
#define DEFAULT_PORT                                "1234"
#define DEFAULT_PROTOCOL_FAMILY     AF_UNSPEC

#define DEFAULT_RECV_MSG_LEN             255

int main(int argc, char* argv[]) {
    kani::SocketInfo info;
    info.m_node = DEFAULT_IP;
    info.m_service = DEFAULT_PORT;
    info.m_protocolFamily = DEFAULT_PROTOCOL_FAMILY;

    kani::TcpClient client(info);

    if (!client.is_valid()) {
        std::cerr << "can't initialized client!" << std::endl;
        return 1;
    }

    if (client.start() != kani::SS_START_RESULT_SUCCESS) {
        std::cerr << "can't start the client!" << std::endl;
        return 1;
    }

    std::cout << "try connecting to server..." << std::endl;

    while (!client.connect()) { }

    std::cout << "server connected!" << std::endl;
    kani::RecvMsg msg(DEFAULT_RECV_MSG_LEN);

    if (!client.recv_msg(&msg)) {
        std::cerr << "can't received message from server!" << std::endl;
        return 1;
    }

    std::cout << "received message from server: " << msg.m_recvLen << "byte" << std::endl;
    std::cout << "Server: " << msg.m_msg << std::endl;

    kani::SendMsg response;
    response.m_msg = "Hello, server! I'm a client. Thank you for your welcome X)";

    if (!client.send_msg(&response)) {
        std::cerr << "can't sent message to server!" << std::endl;
        return 1;
    }

    std::cout << "sent message to server: " << response.m_sentLen << "byte" << std::endl;

    std::cout << "Perfect! Now, say to goodbye :')" << std::endl;
    client.stop();

    std::cout << "disconnected from server" << std::endl;
    return 0;
}