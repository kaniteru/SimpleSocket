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

    kani::UdpClient client(info);

    if (!client.is_valid()) {
        std::cerr << "can't initialized client!" << std::endl;
        return 1;
    }

    if (client.start() != kani::SS_START_RESULT_SUCCESS) {
        std::cerr << "can't start the client!" << std::endl;
        return 1;
    }

    kani::SendMsg msg;
    msg.m_msg = "Hello, server! I'm a client. How are you? :3";

    if (!client.send_msg(&msg)) {
        std::cerr << "can't sent message to server!" << std::endl;
        return 1;
    }

    std::cout << "sent message to server: " << msg.m_sentLen << "byte" << std::endl;

    kani::RecvMsg response(DEFAULT_RECV_MSG_LEN);
    bool isValid = client.recv_msg(&response);

    if (!isValid && response.m_status != kani::SS_MSG_STATUS_SUCCESS_FROM_UNKNOWN_HOST) {
        std::cerr << "can't received message from server!" << std::endl;
        return 1;
    }

    std::cout << "received message from server: " << response.m_recvLen << "byte" << std::endl;
    std::cout << (isValid ? "Server" : "Unknown Server") << ": " << response.m_msg << std::endl;

    std::cout << "Perfect! Now, say to goodbye :')" << std::endl;
    client.stop();
    return 0;
}