# SimpleSocket

Easy to use C++ TCP/UDP socket wrapper

## Features

- **Simple Usage**
- **Single Header**
- **Cross-Platform**
    - Windows
    - Linux
    - Unix (macOS)
    - ...
- **IPv4 and IPv6 Support**
- **C++98 Standard Support**

## Usage

**You can see more example projects [here](https://github.com/kaniteru/SimpleSocket/tree/main/examples).**

```cpp
#include <simple_socket.hpp>
```
```cpp
kani::SocketInfo info;
info.m_node = "localhost"; // host name or ip address
info.m_service = 1234;     // node name or port number
```

### TCP Server

```cpp
kani::TcpServerSocketInfo tcpInfo;
info.m_node = "localhost";
info.m_service = 1234;
info.m_backlog = SOMAXCONN;

kani::TcpServer server(tcpInfo);

if (!server.is_valid() || server.start() != kani::SS_START_RESULT_SUCCESS) {
    return;
}

TcpNetClient client;

while (!server.wait_client(&client)) { }

kani::SendMsg msg("hello world!");
server.send_msg(&client, &msg);

kani::RecvMsg response;
server.recv_msg(&client, &response);

server.stop();
```

### TCP Client

```cpp
kani::TcpClient client(info);

if (!client.is_valid() || client.start() != kani::SS_START_RESULT_SUCCESS) {
    return;
}

if (!client.connect()) {
    return;
}

kani::SendMsg msg("hello world!");
client.send_msg(&msg);

kani::RecvMsg response;
client.recv_msg(&response);

client.stop();
```

### UDP Server

```cpp
kani::UdpServer server(info);

if (!server.is_valid() || server.start() != kani::SS_START_RESULT_SUCCESS) {
    return;
}

NetAddr client;

kani::RecvMsg msg;
server.recv_msg(&client, &msg);

kani::SendMsg response("hello world!");
server.send_msg(&client, &response);

server.stop();
```

### UDP Client

```cpp
kani::UdpClient client(info);

if (!client.is_valid() || client.start() != kani::SS_START_RESULT_SUCCESS) {
    return;
}

kani::SendMsg msg("hello world!");
client.send_msg(&msg);

kani::RecvMsg response;
client.recv_msg(&response);

client.stop();
```

## Todo

- [ ] Add more detailed error types to **eSSMsgStatus**
- [ ] Add more example projects
    - [ ] Thread safe TCP/UDP Server interacting with multiple clients


## License

Unless otherwise specified in subfolders or files, all files in this repository are distributed under the MIT License.

See [LICENSE.txt](https://github.com/kaniteru/SimpleSocket/blob/main/LICENSE.txt) for more information.

<p align="right">[<a href="#SimpleSocket">BACK TO TOP</a>]</p>