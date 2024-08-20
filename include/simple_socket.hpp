/*
 * SimpleSocket
 *
 * @author: kaniteru (kaniteru81@gmail.com)
 * @repo: https://github.com/kaniteru/SimpleSocket
 * */

#ifndef KANITERU_SIMPLE_SOCKET_HPP
#define KANITERU_SIMPLE_SOCKET_HPP

#ifdef _MSVC_LANG
    #define CURRENT_CXX_VERSION _MSVC_LANG
#else
    #define CURRENT_CXX_VERSION __cplusplus
#endif //_MSVC_LANG

// =========================================================
// ===    INCLUDE STANDARD HEADERS
// =========================================================

#include <cstdio>
#include <string>
#include <cstring>

#if CURRENT_CXX_VERSION < 201103L
    #include <stdint.h>
#else
    #include <cstdint>
#endif //CURRENT_CXX_VERSION < 201103L

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
#endif //_WIN32

// =========================================================
// ===    TYPE DEFINES
// =========================================================

typedef int32_t kani_flag_t;

#ifdef _WIN32
    typedef SOCKET kani_socket_t;
    typedef int32_t kani_socklen_t;
    typedef int32_t kani_buflen_t;
#else
    typedef int32_t kani_socket_t;
    typedef uint32_t kani_socklen_t;
    typedef ssize_t kani_buflen_t;
#endif //_WIN32

// =========================================================
// ===    MACRO DEFINES
// =========================================================

#define KANI_MAX_SIZE ((size_t) - 1)
#define KANI_MAX_IP_LEN INET6_ADDRSTRLEN
#define KANI_MAX_PORT_LEN 5
#define KANI_INVALID_BUF_LEN 0
#define KANI_DEFAULT_MAX_MSG_LEN 1024

#ifdef _WIN32
    #define KANI_INVALID_SOCKET INVALID_SOCKET
    #define KANI_SOCKET_ERROR SOCKET_ERROR
    #define KANI_CLOSE_SOCKET(SOCK) closesocket(SOCK);
#else
    #define KANI_INVALID_SOCKET (-1)
    #define KANI_SOCKET_ERROR (-1)
    #define KANI_CLOSE_SOCKET(SOCK) close(SOCK);
#endif //_WIN32

#if CURRENT_CXX_VERSION < 201103L
    #define override
#endif //CURRENT_CXX_VERSION < 201103L

namespace kani {

// ======================= S T R U C T =======================
// ===    Msg
// ======================= S T R U C T =======================

/**
 * @brief Used when a buffer is sent or received.
 *              [ SS = SimpleSocket ]
 */
enum eSSMsgStatus {
    /* Default value. */
    SS_MSG_STATUS_UNKNOWN,
    /* Sent or received success. */
    SS_MSG_STATUS_SUCCESS,
    /* In udp client, received msg success but sender is not the server we want. */
    SS_MSG_STATUS_SUCCESS_FROM_UNKNOWN_HOST,
    /* Received failed, to know the cause, need calling strerror(errno) or WSAGetLastError(). */
    SS_MSG_STATUS_FAILED,
    /* Failed to initialize buffer due to insufficient memory.  */
    SS_MSG_STATUS_FAILED_MAX_BUFFER_LEN_TOO_BIG
};

/**
 * @brief Base of the buffer to send and receive.
 */
struct Msg {
    std::string m_msg; /* Buffer of content received or sent */
    eSSMsgStatus m_status; /* Result of sent or received a buffer */

public:
    Msg();

    /**
     * @param [in] msg Contents of the buffer to initialize.
     */
    explicit Msg(const std::string& msg);

    /**
     * @param [in] pMsg Char pointer for buffer.
     * @param [in] len Buffer length of pStr.
     */
    Msg(const char* pMsg, const size_t& len);
};

inline
Msg::Msg() :
    m_status(SS_MSG_STATUS_UNKNOWN) { }

inline
Msg::Msg(const std::string& msg) :
    m_msg(msg),
    m_status(SS_MSG_STATUS_UNKNOWN) { }

inline
Msg::Msg(const char* pMsg, const size_t& len) :
    m_status(SS_MSG_STATUS_UNKNOWN) {

    m_msg.assign(pMsg, len);
}

// ======================= S T R U C T =======================
// ===    SendMsg
// ======================= S T R U C T =======================

/**
 * @brief Buffer used for send.
 *
 * @code
 * std::string str = "hello world";
 * SendMsg msg(str);
 * @endcode
 *
 * @code
 * const char* pStr = "hello world";
 * size_t len = strlen(pStr);
 * SendMsg msg(pStr, len);
 * @endcode
 */
struct SendMsg : public Msg {
    kani_buflen_t m_sentLen; /* Length of sent buffer */

public:
    SendMsg();

    /**
    * @param [in] msg Buffer to send.
    */
    explicit SendMsg(const std::string& msg);

    /**
    * @param [in] pMsg Char pointer for buffer to send.
    * @param [in] len Buffer length of pStr.
    */
    SendMsg(const char* pMsg, const size_t& len);
};

inline
SendMsg::SendMsg() :
    m_sentLen(0) { }

inline
SendMsg::SendMsg(const std::string& msg) :
    Msg(msg),
    m_sentLen(0) { }

inline
SendMsg::SendMsg(const char* pMsg, const size_t& len) :
    Msg(pMsg, len),
    m_sentLen(0) { }

// ======================= S T R U C T =======================
// ===    RecvMsg
// ======================= S T R U C T =======================

/**
 * @brief Buffer for receive.
 *
 * @code
 * RecvMsg msg;
 * @endcode
 *
 * @code
 * size_t maxLen = 1024;
 * RecvMsg msg(maxLen);
 * @endcode
 */
struct RecvMsg : public Msg {
    kani_buflen_t m_recvLen; /* Length of received buffer */
protected:
    size_t m_maxLen; /* Receivable buffer length, Must be less than 'KANI_MAX_SIZE'. */

public:
    /**
     * @return Receivable buffer length
     */
    const size_t& get_max_len() const;

public:
    /**
     * @param [in] maxLen Maximum buffer length that can be received.
     */
    explicit RecvMsg(const size_t& maxLen = KANI_DEFAULT_MAX_MSG_LEN);
};

inline
const size_t& RecvMsg::get_max_len() const {
    return m_maxLen;
}

inline
RecvMsg::RecvMsg(const size_t& maxLen) :
    m_recvLen(0),
    m_maxLen(maxLen) { }

// ======================= S T R U C T =======================
// ===    SocketInfo
// ======================= S T R U C T =======================

/**
 * @brief Components required when initializing a socket.
 */
struct SocketInfo {
    std::string m_node; /* Host name or ip address */
    std::string m_service; /* Service name or port number */
    int32_t m_protocolFamily; /* Use 'AF_INET' for ipv4 and 'AF_INET6' for ipv6. */
};

// ======================= S T R U C T =======================
// ===    SocketHints
// ======================= S T R U C T =======================

/**
 * @brief Components required when initializing a socket.
 */
struct SocketHints {
    bool m_isTcp; /* Should be false if you want udp socket */
    bool m_isServer; /* Should be false if you want a client socket */
};

// ======================== C L A S S ========================
// ===    ISocket
// ======================== C L A S S ========================

/**
 * @brief Used to return whether the socket is initialized or not.
 */
enum eSSStartResult {
    SS_START_RESULT_SUCCESS = 0,
    SS_START_RESULT_FAILED_ALREADY_STARTED = 1,
    SS_START_RESULT_FAILED_CREATE_SOCKET = 2,
    SS_START_RESULT_FAILED_BIND_SOCKET = 3,
    SS_START_RESULT_FAILED_LISTEN_SOCKET = 4,
};

/**
 * @brief Server and Client Interface.
 *              Helps initialize the socket.
 */
class ISocket {
public:
    /**
     * @brief Before calling start(), you should call this method to ensure that the socket can be initialized.
     *
     * @return Returns true when the socket is ready to be initialized.
     */
    const bool& is_valid() const;

    /**
     * @brief This should initialize the socket and start the server or client.
     *
     * @return Returns whether the socket was initialized and the server or client started successfully.
     */
    virtual eSSStartResult start() = 0;

    /**
     * @brief This should shutdown the server or client and close the socket.
     */
    virtual void stop() = 0;
protected:
    /**
     * @brief Initialize addrinfo with the supplied args.
     *              It starts working after zerofilling addrinfo, so if you want to insert additional hints into addrinfo, you should do so after calling this method.
     *
     * @param [in, out] pHints addrinfo to use as hints.
     * @param [in] pSockHints SocketHints of the options to reference when initializing addrinfo.
     */
    static void get_addrinfo_hints(addrinfo& hints, const SocketHints& socHints);

    /**
     * @brief Initialize the m_pAddrInfo by referencing SocketInfo and SocketHints.
     *
     * @param [in] info
     * @param [in] socHints
     * @return Returns false if the information provided in SocketInfo or SocketHints is invalid.
     */
    bool parse_socketinfo(const SocketInfo& info, const SocketHints& socHints);

public:
    ISocket();

    /**
     * @brief Close the socket and free m_pAddrInfo.
     */
    ~ISocket();
protected:
    bool m_isValid; /* Is socket can be initialized? */
    kani_socket_t m_socket; /* Socket on the server or client */
    addrinfo* m_pAddrInfo; /* Required when creating a socket */
private:
#ifdef _WIN32
    WSAData m_wsaData; /* Required on win32 only */
#endif
};

inline
const bool& ISocket::is_valid() const {
    return m_isValid;
}

inline
void ISocket::get_addrinfo_hints(addrinfo& hints, const SocketHints& socHints) {
    memset(&hints, 0, sizeof(hints));

    if (socHints.m_isTcp) {
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
    } else {
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
    }

    if (socHints.m_isServer) {
        hints.ai_flags = AI_PASSIVE;
    }
}

inline
bool ISocket::parse_socketinfo(const SocketInfo& info, const SocketHints& socHints) {
    addrinfo hints;
    get_addrinfo_hints(hints, socHints);

    hints.ai_family = info.m_protocolFamily;

    return getaddrinfo(info.m_node.c_str(), info.m_service.c_str(), &hints, &m_pAddrInfo) == 0;
}

inline
ISocket::ISocket() :
        m_isValid(true),
        m_socket(KANI_INVALID_SOCKET),
        m_pAddrInfo(NULL) {

#ifdef _WIN32
    if (WSAStartup(MAKEWORD(2, 2), &m_wsaData) != 0) {
        m_isValid = false;
    }
#endif
}

inline
ISocket::~ISocket() {
    if (m_socket != KANI_INVALID_SOCKET) {
        KANI_CLOSE_SOCKET(m_socket);
        m_socket = KANI_INVALID_SOCKET;
    }

    if (m_pAddrInfo) {
        freeaddrinfo(m_pAddrInfo);
        m_pAddrInfo = NULL;
    }

#ifdef _WIN32
    WSACleanup();
#endif
}

// ======================== C L A S S ========================
// ===    IClient
// ======================== C L A S S ========================

/**
 * @brief Client Interface
 */
class IClient {
public:
    /**
     * @brief This should send a message to the server.
     *
     * @param [in, out] pMsg
     * @param [in] flag Flags for send() or sendto().
     * @return Returns true if the message was sent successfully.
     */
    virtual bool send_msg(SendMsg* pMsg, const kani_flag_t& flag = 0) = 0;

    /**
     * @brief This should receive a message from the server.
     *
     * @param [in, out] pMsg
     * @param [in] flag Flags for recv() or recvfrom().
     * @return Returns true if the message was successfully received from the server.
     */
    virtual bool recv_msg(RecvMsg* pMsg, const kani_flag_t& flag = 0) = 0;
};

// ======================== C L A S S ========================
// ===    NetAddr
// ======================== C L A S S ========================

/**
 * @brief It helps check the IP and PORT.
 */
class NetAddr {
public:
    /**
     * @return Returns sockaddr_storage.
     */
    const sockaddr_storage& get_addr() const;

    /**
     * @return Returns IP string.
     */
    const std::string& get_ip() const;

    /**
     * @return Returns PORT string.
     */
    const std::string& get_port() const;

protected:
    /**
     * @brief Initialize the m_ip and m_port by referencing the m_addr.
     *              After initializing m_addr in the constructor, you should call this method.
     *
     * @param [in] flags Flags for getnameinfo().
     * @return Returns false if m_addr is invalid or getnameinfo fails.
     */
    bool parse_addr(const kani_flag_t& flags = NI_NUMERICHOST | NI_NUMERICSERV);

public:
    NetAddr();

    /**
     * @param [in] addr
     */
    explicit NetAddr(const sockaddr_storage& addr);

    /**
     * @param [in] addr
     */
    explicit NetAddr(const addrinfo& addr);
protected:
    sockaddr_storage m_addr;
    std::string m_ip;
    std::string m_port;
};

inline
const sockaddr_storage& NetAddr::get_addr() const {
    return m_addr;
}

inline
const std::string& NetAddr::get_ip() const {
    return m_ip;
}

inline
const std::string& NetAddr::get_port() const {
    return m_port;
}

inline
bool NetAddr::parse_addr(const kani_flag_t& flags) {
    char ip[KANI_MAX_IP_LEN + 1];
    char port[KANI_MAX_PORT_LEN + 1];
    memset(ip, 0, sizeof(ip));
    memset(port, 0, sizeof(port));

    if (getnameinfo(reinterpret_cast<sockaddr*>(&m_addr), sizeof(m_addr), ip, sizeof(ip), port, sizeof(port), flags) != 0) {
        return false;
    }

    m_ip.assign(ip);
    m_port.assign(port);
    return true;
}

inline
NetAddr::NetAddr() { }

inline
NetAddr::NetAddr(const sockaddr_storage& addr) :
        m_addr(addr) {

    this->parse_addr();
}

inline
NetAddr::NetAddr(const addrinfo& addr) {
    memset(&m_addr, 0, sizeof(m_addr));
    memcpy(&m_addr, addr.ai_addr, addr.ai_addrlen);

    this->parse_addr();
}

// ======================== C L A S S ========================
// ===    TcpMsgHelper
// ======================== C L A S S ========================

/**
 * @brief Helps send and receive messages on Tcp socket.
 */
class TcpMsgHelper {
public:
    /**
     * @brief Send a message to the socket.
     *
     * @param [in] pSocket
     * @param [in, out] pMsg
     * @param [in] flag Flags for send().
     * @return Returns true if the message was sent successfully.
     *
     * @code
     * kani_socket_t socket = ...;
     * SendMsg msg(...);
     *
     * if (TcpMsgHelper::send_msg(&socket, &msg, ...)) { ... }
     * @endcode
     */
    static bool send_msg(const kani_socket_t* pSocket, SendMsg* pMsg, const kani_flag_t& flag);

    /**
     * @brief Receive a message from the socket.
     *
     * @param [in] pSocket
     * @param [in, out] pMsg
     * @param [in] flag Flags for recv().
     * @return Returns true if the message was received successfully.
     *
     * @code
     * kani_socket_t socket = ...;
     * RecvMsg msg(...);
     *
     * if (TcpMsgHelper::recv_msg(&socket, &msg, ...)) { ... }
     * @endcode
     */
    static bool recv_msg(const kani_socket_t* pSocket, RecvMsg* pMsg, const kani_flag_t& flag);
};

inline
bool TcpMsgHelper::send_msg(const kani_socket_t* pSocket, SendMsg* pMsg, const kani_flag_t& flag) {
    if (!pSocket || !pMsg) {
        return false;
    }

    const std::string& str = pMsg->m_msg;

    pMsg->m_sentLen = send(*pSocket, str.c_str(), str.length(), flag);

    if (pMsg->m_sentLen <= KANI_INVALID_BUF_LEN) {
        pMsg->m_status = SS_MSG_STATUS_FAILED;
        return false;
    }

    pMsg->m_status = SS_MSG_STATUS_SUCCESS;
    return true;
}

inline
bool TcpMsgHelper::recv_msg(const kani_socket_t* pSocket, RecvMsg* pMsg, const kani_flag_t& flag) {
    if (!pSocket || !pMsg) {
        return false;
    }

    const size_t& maxLen = pMsg->get_max_len();
    const size_t strlen = maxLen >= KANI_MAX_SIZE ? maxLen : (maxLen + 1);
    char* pStr;

    try {
        pStr = new char[strlen];
    } catch (const std::bad_alloc&) {
        pMsg->m_status = SS_MSG_STATUS_FAILED_MAX_BUFFER_LEN_TOO_BIG;
        return false;
    }

    memset(pStr, 0, strlen);
    pMsg->m_recvLen = recv(*pSocket, pStr, strlen, flag);

    if (pMsg->m_recvLen <= KANI_INVALID_BUF_LEN) {
        pMsg->m_status = SS_MSG_STATUS_FAILED;
        return false;
    }

    pMsg->m_msg.assign(pStr);
    pMsg->m_status = SS_MSG_STATUS_SUCCESS;

    delete[] pStr;
    pStr = NULL;
    return true;
}

// ======================== C L A S S ========================
// ===    UdpMsgHelper
// ======================== C L A S S ========================

/**
 * @brief Helps send and receive messages on Udp socket.
 */
class UdpMsgHelper {
public:
    /**
     * @brief Send a message to the sockaddr.
     *
     * @param [in] pSocket
     * @param [in, out] pMsg
     * @param [in] pAddr
     * @param [in] pAddrLen
     * @param [in] flag Flags for sendto().
     * @return Returns true if the message was sent successfully.
     *
     * @code
     * kani_socket_t socket = ...;
     * SendMsg msg(...);
     * sockaddr_storage addr = ...;
     * kani_socklent_t addrLen = sizeof(addr);
     *
     * if (UdpMsgHelper::send_msg(&socket, &msg, reinterpret_cast<sockaddr*>(&addr), addrLen, ...)) { ... }
     * @endcode
     */
    static bool send_msg(const kani_socket_t* pSocket, SendMsg* const pMsg, const sockaddr* pAddr, const kani_socklen_t& pAddrLen, const kani_flag_t& flag);

    /**
     * @brief Send a message to the NetAddr.
     *
     * @param [in] pSocket
     * @param [in, out] pMsg
     * @param [in] pNetAddr
     * @param [in] flag Flags for sendto().
     * @return Returns true if the message was sent successfully.
     *
     * @code
     * kani_socket_t socket = ...;
     * SendMsg msg(...);
     * NetAddr addr(...);
     *
     * if (UdpMsgHelper::send_msg(&socket, &msg, &addr, ...)) { ... }
     * @endcode
     */
    static bool send_msg(const kani_socket_t* pSocket, SendMsg* const pMsg, const NetAddr* pNetAddr, const kani_flag_t& flag);

    /**
     * @brief Receive incoming messages on the socket.
     *
     * @param [in] pSocket
     * @param [in, out] pMsg
     * @param [in, out, optional] pAddr
     * @param [in, out, optional] pAddrLen
     * @param [in] flag Flags for recvfrom().
     * @return Returns true if the message was received successfully.
     *
     * @code
     * kani_socket_t socket = ...;
     * RecvMsg msg(...);
     * sockaddr_storage addr;
     * kani_socklent_t addrLen = sizeof(addr);
     *
     * if (UdpMsgHelper::recv_msg(&socket, &msg, reinterpret_cast<sockaddr*>(&addr), &addrLen, ...)) { ... }
     * @endcode
     *
     * @code
     * if (UdpMsgHelper::recv_msg(&socket, &msg, NULL, NULL, ...)) { ... }
     * @endcode
     */
    static bool recv_msg(const kani_socket_t* pSocket, RecvMsg* const pMsg, sockaddr* const pAddr, kani_socklen_t* const pAddrLen, const kani_flag_t& flag);

    /**
     * @brief Receive incoming messages on the socket.
     *
     * @param [in] pSocket
     * @param [in, out] pMsg
     * @param [in, out, optional] pNetAddr
     * @param [in] flag Flags for recvfrom().
     * @return Returns true if the message was received successfully.
     *
     * @code
     * kani_socket_t socket = ...;
     * RecvMsg msg(...);
     * NetAddr addr;
     *
     * if (UdpMsgHelper::recv_msg(&socket, &msg, &addr, ...)) { ... }
     * @endcode
     *
     * @code
     * if (UdpMsgHelper::recv_msg(&socket, &msg, NULL, ...)) { ... }
     * @endcode
     */
    static bool recv_msg(const kani_socket_t* pSocket, RecvMsg* const pMsg, NetAddr* const pNetAddr, const kani_flag_t& flag);
};

inline
bool UdpMsgHelper::send_msg(const kani_socket_t* pSocket, SendMsg* const pMsg, const sockaddr* pAddr, const kani_socklen_t& pAddrLen, const kani_flag_t& flag) {
    if (!pSocket || !pMsg || !pAddr) {
        return false;
    }

    const std::string& str = pMsg->m_msg;

    pMsg->m_sentLen = sendto(*pSocket, str.c_str(), str.length(), flag, pAddr, pAddrLen);

    if (pMsg->m_sentLen <= KANI_INVALID_BUF_LEN) {
        pMsg->m_status = SS_MSG_STATUS_FAILED;
        return false;
    }

    pMsg->m_status = SS_MSG_STATUS_SUCCESS;
    return true;
}

inline
bool UdpMsgHelper::send_msg(const kani_socket_t* pSocket, SendMsg* const pMsg, const NetAddr* pNetAddr, const kani_flag_t& flag) {
    if (!pNetAddr) {
        return false;
    }

    sockaddr_storage addr = pNetAddr->get_addr();
    kani_socklen_t len = sizeof(addr);
    return send_msg(pSocket, pMsg, reinterpret_cast<sockaddr*>(&addr), len, flag);
}

inline
bool UdpMsgHelper::recv_msg(const kani_socket_t* pSocket, RecvMsg* const pMsg, sockaddr* const pAddr, kani_socklen_t* const pAddrLen, const kani_flag_t& flag) {
    if (!pSocket || !pMsg) {
        return false;
    }

    const size_t& maxLen = pMsg->get_max_len();
    const size_t strlen = maxLen >= KANI_MAX_SIZE ? maxLen : (maxLen + 1);
    char* pStr;

    try {
        pStr = new char[strlen];
    } catch (const std::bad_alloc&) {
        pMsg->m_status = SS_MSG_STATUS_FAILED_MAX_BUFFER_LEN_TOO_BIG;
        return false;
    }

    memset(pStr, 0, strlen);
    pMsg->m_recvLen = recvfrom(*pSocket, pStr, strlen, flag, pAddr, pAddrLen);

    if (pMsg->m_recvLen <= KANI_INVALID_BUF_LEN) {
        pMsg->m_status = SS_MSG_STATUS_FAILED;
        return false;
    }

    pMsg->m_msg.assign(pStr);
    pMsg->m_status = SS_MSG_STATUS_SUCCESS;

    delete[] pStr;
    pStr = NULL;
    return true;
}

inline
bool UdpMsgHelper::recv_msg(const kani_socket_t* pSocket, RecvMsg* const pMsg, NetAddr* const pNetAddr, const kani_flag_t& flag) {
    if (!pNetAddr) {
        return recv_msg(pSocket, pMsg, NULL, NULL, flag);
    }

    sockaddr_storage addr;
    kani_socklen_t len = sizeof(addr);
    memset(&addr, 0, len);

    if (!recv_msg(pSocket, pMsg, reinterpret_cast<sockaddr*>(&addr), &len, flag)) {
        return false;
    }

    *pNetAddr = NetAddr(addr);
    return true;
}

// ======================== C L A S S ========================
// ===    TcpNetClient
// ======================== C L A S S ========================

/**
 * @brief Control connected client in TcpServer.
 */
class TcpNetClient : public NetAddr {
public:
    /**
    * @return Returns the socket ID.
    */
    const kani_socket_t& get_socket() const;

    /**
     * @return Returns true if the client socket is closed.
     */
    bool is_disconnected() const;

    /**
     * @brief Close the client socket.
     */
    void disconnect();

public:
    TcpNetClient();

    /**
     * @param [in] addr
     */
    explicit TcpNetClient(const sockaddr_storage& addr);

    /**
     * @param [in] socket
     * @param [in] addr
     */
    TcpNetClient(const kani_socket_t& socket, const sockaddr_storage& addr);
private:
    kani_socket_t m_socket;
};

inline
const kani_socket_t& TcpNetClient::get_socket() const {
    return m_socket;
}

inline
bool TcpNetClient::is_disconnected() const {
    return m_socket == KANI_INVALID_SOCKET;
}

inline
void TcpNetClient::disconnect() {
    if (this->is_disconnected()) {
        return;
    }

    KANI_CLOSE_SOCKET(m_socket);
    m_socket = KANI_INVALID_SOCKET;
}

inline
TcpNetClient::TcpNetClient() :
        m_socket(KANI_INVALID_SOCKET) { }

inline
TcpNetClient::TcpNetClient(const sockaddr_storage& addr) :
        m_socket(KANI_INVALID_SOCKET),
        NetAddr(addr) { }

inline
TcpNetClient::TcpNetClient(const kani_socket_t& socket, const sockaddr_storage& addr) :
        m_socket(socket),
        NetAddr(addr) { }

// ======================= S T R U C T =======================
// ===    TcpServerSocketInfo
// ======================= S T R U C T =======================

/**
 * @brief SocketInfo used when initializing TcpServer.
 */
struct TcpServerSocketInfo : public SocketInfo {
    int32_t m_backlog; /* Queue limits in wait_client(),The maximum value is 'SOMAXCONN' */
};

// ======================== C L A S S ========================
// ===    TcpServer
// ======================== C L A S S ========================

/**
 * @brief TcpServer
 */
class TcpServer : public ISocket {
public:
    /**
     * @brief Start the server.
     *
     * @return Returns 'SS_START_RESULT_SUCCESS' if the server started successfully.
     *
     * @code
     * TcpServer server(...);
     *
     * if (server.is_valid() && server.start() == SS_START_RESULT_SUCCESS) { ... }
     * @endcode
     */
    virtual eSSStartResult start() override;

    /**
     * @brief Check for incoming client to the server.
     *
     * @param [in, out] pClient
     * @return Returns true when the client is connected and initialises pClient.
     *
     * @code
     * TcpServer server(...);
     * TcpNetClient client;
     *
     * while(true) {
     *     if (server.wait_client(&client)) { ... }
     * }
     * @endcode
     */
    bool wait_client(TcpNetClient* pClient);

    /**
     * @brief Sends a message to the client.
     *
     * @param [in] pClient
     * @param [in, out] pMsg
     * @param [in] flag Flags for send().
     * @return Returns true if sent successfully.
     *
     * @code
     * TcpServer server(...);
     * TcpNetClient client(...);
     * SendMsg msg(...);
     *
     * if (server.send_msg(&client, &msg, ...)) { ... }
     * @endcode
     */
    bool send_msg(TcpNetClient* pClient, SendMsg* pMsg, const kani_flag_t& flag = 0) const;

    /**
     * @brief Receive a message from the client.
     *
     * @param [in] pClient
     * @param [in, out] pMsg
     * @param [in] flag Flags for recv().
     * @return Returns true if received successfully.
     *
     * @code
     * TcpServer server(...);
     * TcpNetClient client(...);
     * RecvMsg msg(...);
     *
     * if (server.recv_msg(&client, &msg, ...)) { ... }
     * @endcode
     */
    bool recv_msg(TcpNetClient* pClient, RecvMsg* pMsg, const kani_flag_t& flag = 0) const;

    /**
     * @brief Shutdown the server.
     */
    virtual void stop() override;

public:
    /**
     * @param [in] info
     */
    explicit TcpServer(const TcpServerSocketInfo& info);
    ~TcpServer();
protected:
    int32_t m_backlog;
};

inline
eSSStartResult TcpServer::start() {
    if (m_socket != KANI_INVALID_SOCKET) {
        return SS_START_RESULT_FAILED_ALREADY_STARTED;
    }

    m_socket = socket(m_pAddrInfo->ai_family, m_pAddrInfo->ai_socktype, m_pAddrInfo->ai_protocol);

    if (m_socket == KANI_INVALID_SOCKET) {
        return SS_START_RESULT_FAILED_CREATE_SOCKET;
    }

    if (bind(m_socket, m_pAddrInfo->ai_addr, m_pAddrInfo->ai_addrlen) == KANI_SOCKET_ERROR) {
        this->stop();
        return SS_START_RESULT_FAILED_BIND_SOCKET;
    }

    if (listen(m_socket, m_backlog) == KANI_SOCKET_ERROR) {
        this->stop();
        return SS_START_RESULT_FAILED_LISTEN_SOCKET;
    }

    return SS_START_RESULT_SUCCESS;
}

inline
bool TcpServer::wait_client(TcpNetClient* pClient) {
    if (!pClient) {
        return false;
    }

    sockaddr_storage addr;
    kani_socklen_t addrLen = sizeof(addr);
    memset(&addr, 0, sizeof(addr));

    kani_socket_t socket = accept(m_socket, reinterpret_cast<sockaddr*>(&addr), &addrLen);

    if (socket == KANI_INVALID_SOCKET) {
        return false;
    }

    *pClient = TcpNetClient(socket, addr);
    return true;
}

inline
bool TcpServer::send_msg(TcpNetClient* pClient, SendMsg* pMsg, const kani_flag_t& flag) const {
    if (!pClient) {
        return false;
    }

    return TcpMsgHelper::send_msg(&pClient->get_socket(), pMsg, flag);
}

inline
bool TcpServer::recv_msg(TcpNetClient* pClient, RecvMsg* pMsg, const kani_flag_t& flag) const {
    if (!pClient) {
        return false;
    }

    return TcpMsgHelper::recv_msg(&pClient->get_socket(), pMsg, flag);
}

inline
void TcpServer::stop() {
    if (m_socket == KANI_INVALID_SOCKET) {
        return;
    }

    KANI_CLOSE_SOCKET(m_socket);
    m_socket = KANI_INVALID_SOCKET;
}

inline
TcpServer::TcpServer(const TcpServerSocketInfo& info) {
    if (!m_isValid) {
        return;
    }

    m_backlog = info.m_backlog;

    SocketHints hints;
    hints.m_isTcp = true;
    hints.m_isServer = true;

    if (!this->parse_socketinfo(info, hints)) {
        m_isValid = false;
        return;
    }
}

inline
TcpServer::~TcpServer() { }

// ======================== C L A S S ========================
// ===    TcpClient
// ======================== C L A S S ========================

/**
 * @brief TcpClient
 */
class TcpClient : public ISocket, public IClient {
public:
    /**
     * @brief Start the client.
     *
     * @return Returns 'SS_START_RESULT_SUCCESS' upon successful initialization.
     *
     * @code
     * TcpClient client(...);
     *
     * if (client.is_valid() && client.start() == SS_START_RESULT_SUCCESS) { ... }
     * @endcode
     */
    virtual eSSStartResult start() override;

    /**
     * @brief Connect to the server.
     *
     * @return Returns true if connected to a server.
     *
     * @code
     * TcpClient client(...);
     *
     * if (client.is_valid() && client.start() == SS_START_RESULT_SUCCESS) {
     *     if (client.connect()) { ... }
     * }
     * @endcode
     */
    bool connect();

    /**
     * @brief Send a message to the server.
     *
     * @param [in, out] pMsg
     * @param [in] flag Flags for sendto().
     * @return Returns true if the message was sent successfully.
     *
     * @code
     * TcpClient client(...);
     * SendMsg msg(...);
     *
     * if (client.send_msg(&msg, ...)) { ... }
     * @endcode
     */
    virtual bool send_msg(SendMsg* pMsg, const kani_flag_t& flag = 0) override;

    /**
     * @brief Receive a message from the server.
     *
     * @param [in, out] pMsg
     * @param [in] flag Flags for recvfrom().
     * @return Returns true if the message was received successfully.
     *
     * @code
     * TcpClient client(...);
     * RecvMsg msg(...);
     *
     * if (client.recv_msg(&msg, ...)) { ... }
     * @endcode
     */
    virtual bool recv_msg(RecvMsg* pMsg, const kani_flag_t& flag = 0) override;

    /**
     * @brief Shutdown the client.
     *              If you want reconnect to the server, you must call start() before calling connect().
     */
    virtual void stop() override;

public:
    /**
     * @param [in] info
     */
    explicit TcpClient(const SocketInfo& info);
    ~TcpClient();
};

inline
eSSStartResult TcpClient::start() {
    if (m_socket != KANI_INVALID_SOCKET) {
        return SS_START_RESULT_FAILED_ALREADY_STARTED;
    }

    m_socket = socket(m_pAddrInfo->ai_family, m_pAddrInfo->ai_socktype, m_pAddrInfo->ai_protocol);

    if (m_socket == KANI_INVALID_SOCKET) {
        return SS_START_RESULT_FAILED_CREATE_SOCKET;
    }

    return SS_START_RESULT_SUCCESS;
}

inline
bool TcpClient::connect() {
    return ::connect(m_socket, m_pAddrInfo->ai_addr, m_pAddrInfo->ai_addrlen) != KANI_SOCKET_ERROR;
}

inline
bool TcpClient::send_msg(SendMsg* pMsg, const kani_flag_t& flag) {
    return TcpMsgHelper::send_msg(&m_socket, pMsg, flag);
}

inline
bool TcpClient::recv_msg(RecvMsg* pMsg, const kani_flag_t& flag) {
    return TcpMsgHelper::recv_msg(&m_socket, pMsg, flag);
}

inline
void TcpClient::stop() {
    if (m_socket == KANI_INVALID_SOCKET) {
        return;
    }

    KANI_CLOSE_SOCKET(m_socket);
    m_socket = KANI_INVALID_SOCKET;
}

inline
TcpClient::TcpClient(const SocketInfo& info) {
    if (!m_isValid) {
        return;
    }

    SocketHints hints;
    hints.m_isTcp = true;
    hints.m_isServer = false;

    if (!this->parse_socketinfo(info, hints)) {
        m_isValid = false;
    }
}

inline
TcpClient::~TcpClient() { }

// ======================== C L A S S ========================
// ===    UdpServer
// ======================== C L A S S ========================

/**
 * @brief UdpServer
 */
class UdpServer : public ISocket {
public:
    /**
     * @brief Start the server.
     *
     * @return Returns 'SS_START_RESULT_SUCCESS' if the server started successfully.
     *
     * @code
     * UdpServer server(...);
     *
     * if (server.is_valid() && server.start() == SS_START_RESULT_SUCCESS) { ... }
     * @endcode
     */
    virtual eSSStartResult start() override;

    /**
     * @brief Sends a message to the client.
     *
     * @param [in] pClient
     * @param [in, out] pMsg
     * @param [in] flag Flags for sendto().
     * @return Returns true if sent successfully.
     *
     * @code
     * UdpServer server(...);
     * NetAddr client(...);
     * SendMsg msg(...);
     *
     * if (server.send_msg(&client, &msg, ...)) { ... }
     * @endcode
     */
    bool send_msg(NetAddr* pClient, SendMsg* pMsg, const kani_flag_t& flag = 0);

    /**
     * @brief Receive a message from the client.
     *
     * @param [in, out, optional] pClient
     * @param [in, out] pMsg
     * @param [in] flag Flags for recvfrom().
     * @return Returns true if received successfully.
     *
     * @code
     * UdpServer server(...);
     * NetAddr client;
     * RecvMsg msg(...);
     *
     * if (server.recv_msg(&client, &msg, ...)) { ... }
     * -------------------------------------------
     * if (server.recv_msg(NULL, &msg, ...)) { ... }
     * @endcode
     */
    bool recv_msg(NetAddr* pClient, RecvMsg* pMsg, const kani_flag_t& flag = 0);

    /**
     * @brief Shutdown the server.
     */
    virtual void stop() override;

public:
    /**
     * @param [in] info
     */
    explicit UdpServer(const SocketInfo& info);
    ~UdpServer();
};

inline
eSSStartResult UdpServer::start() {
    if (m_socket != KANI_INVALID_SOCKET) {
        return SS_START_RESULT_FAILED_ALREADY_STARTED;
    }

    m_socket = socket(m_pAddrInfo->ai_family, m_pAddrInfo->ai_socktype, m_pAddrInfo->ai_protocol);

    if (m_socket == KANI_INVALID_SOCKET) {
        return SS_START_RESULT_FAILED_CREATE_SOCKET;
    }

    if (bind(m_socket, m_pAddrInfo->ai_addr, m_pAddrInfo->ai_addrlen) == KANI_SOCKET_ERROR) {
        this->stop();
        return SS_START_RESULT_FAILED_BIND_SOCKET;
    }

    return SS_START_RESULT_SUCCESS;
}

inline
bool UdpServer::send_msg(NetAddr* pClient, SendMsg* pMsg, const kani_flag_t& flag) {
    if (!pClient || !pMsg) {
        return false;
    }

    return UdpMsgHelper::send_msg(&m_socket, pMsg, pClient, flag);
}

inline
bool UdpServer::recv_msg(NetAddr* pClient, RecvMsg* pMsg, const kani_flag_t& flag) {
    if (!pMsg) {
        return false;
    }

    return UdpMsgHelper::recv_msg(&m_socket, pMsg, pClient, flag);
}

inline
void UdpServer::stop() {
    if (m_socket == KANI_INVALID_SOCKET) {
        return;
    }

    KANI_CLOSE_SOCKET(m_socket);
    m_socket = KANI_INVALID_SOCKET;
}

inline
UdpServer::UdpServer(const SocketInfo& info) {
    if (!m_isValid) {
        return;
    }

    SocketHints hints;
    hints.m_isTcp = false;
    hints.m_isServer = true;

    if (!this->parse_socketinfo(info, hints)) {
        m_isValid = false;
    }
}

inline
UdpServer::~UdpServer() { }

// ======================== C L A S S ========================
// ===    UdpClient
// ======================== C L A S S ========================

/**
 * @brief UdpClient
 */
class UdpClient : public ISocket, public IClient {
public:
    /**
     * @brief Start the client.
     *
     * @return Returns 'SS_START_RESULT_SUCCESS' upon successful initialization.
     *
     * @code
     * UdpClient client(...);
     *
     * if (client.is_valid() && client.start() == SS_START_RESULT_SUCCESS) { ... }
     * @endcode
     */
    virtual eSSStartResult start() override;

    /**
     * @brief Send a message to the server.
     *
     * @param [in, out] pMsg
     * @param [in] flag Flags for sendto().
     * @return Returns true if the message was sent successfully.
     *
     * @code
     * UdpClient client(...);
     * SendMsg msg(...);
     *
     * if (client.send_msg(&msg, ...)) { ... }
     * @endcode
     */
    virtual bool send_msg(SendMsg* pMsg, const kani_flag_t& flag = 0) override;

    /**
     * @brief Receive a message from the server.
     *
     * @param [in, out] pMsg
     * @param [in] flag Flags for recvfrom().
     * @return Returns true if the message was received successfully.
     *
     * @code
     * UdpClient client(...);
     * RecvMsg msg(...);
     *
     * if (client.recv_msg(&msg, ...)) { ... }
     * @endcode
     */
    virtual bool recv_msg(RecvMsg* pMsg, const kani_flag_t& flag = 0) override;

    /**
     * @brief Shutdown the client.
     *              If you want to receive or send messages again, you should call start().
     */
    virtual void stop() override;

public:
    explicit UdpClient(const SocketInfo& info);
    ~UdpClient();
protected:
    NetAddr m_netServer;
};

inline
eSSStartResult UdpClient::start() {
    if (m_socket != KANI_INVALID_SOCKET) {
        return SS_START_RESULT_FAILED_ALREADY_STARTED;
    }

    m_socket = socket(m_pAddrInfo->ai_family, m_pAddrInfo->ai_socktype, m_pAddrInfo->ai_protocol);

    if (m_socket == KANI_INVALID_SOCKET) {
        return SS_START_RESULT_FAILED_CREATE_SOCKET;
    }

    return SS_START_RESULT_SUCCESS;
}

inline
bool UdpClient::send_msg(SendMsg* pMsg, const kani_flag_t& flag) {
    return UdpMsgHelper::send_msg(&m_socket, pMsg, m_pAddrInfo->ai_addr, m_pAddrInfo->ai_addrlen, flag);
}

inline
bool UdpClient::recv_msg(RecvMsg* pMsg, const kani_flag_t& flag) {
    NetAddr sender;

    if (!UdpMsgHelper::recv_msg(&m_socket, pMsg, &sender, flag)) {
        return false;
    }

    if ((m_netServer.get_ip() == sender.get_ip()) && (m_netServer.get_port() == sender.get_port())) {
        return true;
    }

    pMsg->m_status = SS_MSG_STATUS_SUCCESS_FROM_UNKNOWN_HOST;
    return false;
}

inline
void UdpClient::stop() {
    if (m_socket == KANI_INVALID_SOCKET) {
        return;
    }

    KANI_CLOSE_SOCKET(m_socket);
    m_socket = KANI_INVALID_SOCKET;
}

inline
UdpClient::UdpClient(const SocketInfo& info) {
    if (!m_isValid) {
        return;
    }

    SocketHints hints;
    hints.m_isTcp = false;
    hints.m_isServer = false;

    if (!this->parse_socketinfo(info, hints)) {
        m_isValid = false;
        return;
    }

    m_netServer = NetAddr(*m_pAddrInfo);
}

inline
UdpClient::~UdpClient() { }
}


#endif //KANITERU_SIMPLE_SOCKET_HPP
