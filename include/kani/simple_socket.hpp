/*
 * SimpleSocket
 *
 * @author: kaniteru (kaniteru81@gmail.com)
 * @repo: https://github.com/kaniteru/SimpleSocket
 **/

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
    #include <cerrno>
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

#define KANI_MAX_SIZE                           ((size_t) - 1)
#define KANI_MAX_BUF_LEN                    ((kani_buflen_t) - 1)
#define KANI_MAX_UDP_BUF_LEN           65507
#define KANI_INVALID_BUF_LEN             0
#define KANI_DEFAULT_MAX_MSG_LEN 65535

#ifdef _WIN32
    #define KANI_INVALID_SOCKET         INVALID_SOCKET
    #define KANI_SOCKET_ERROR            SOCKET_ERROR
    #define KANI_CLOSE_SOCKET(SOCK) closesocket(SOCK);
#else
    #define KANI_INVALID_SOCKET        (-1)
    #define KANI_SOCKET_ERROR            (-1)
    #define KANI_CLOSE_SOCKET(SOCK) ::close(SOCK);
#endif //_WIN32

#if CURRENT_CXX_VERSION < 201103L
    #define override
    #define KANI_NULLPTR NULL
#else
    #define KANI_NULLPTR nullptr
#endif //CURRENT_CXX_VERSION < 201103L

#if CURRENT_CXX_VERSION >= 201703L
    #define KANI_STRVIEW std::string_view
#else
    #define KANI_STRVIEW const std::string&
#endif //CURRENT_CXX_VERSION >= 201703L

#ifdef KANITERU_ASYNC_SOCKET_INCLUDED
    #define KANITERU_SIMPLE_SOCKET_CHECKED_ASYNC_SOCKET_INCLUDE
namespace kani {
namespace async_socket {
    class ISocket;
} //namespace async_socket
} //namespace kani
#endif //KANITERU_ASYNC_SOCKET_INCLUDED

namespace kani {
namespace simple_socket {
// ======================= S T R U C T =======================
// ===    Msg
// ======================= S T R U C T =======================

/**
 * @brief Using get status when buffer is sent or received.
 *              [ SS = SimpleSocket ]
 */
enum eSSMsgStatus : int32_t {
    /* Received failed, to know the cause, using SocketErrTracker */
    SS_MSG_STATUS_UNKNOWN                                              = -1,
    /* Sent or received success. */
    SS_MSG_STATUS_SUCCESS                                                 = 0,
    /* Failed, using GetWsaLastError() or errno to can track the error. */
    SS_MSG_STATUS_FAILED                                                     = 1,
    /* In the udp client, received msg success but sender isn't the server we want. */
    SS_MSG_STATUS_SUCCESS_FROM_UNKNOWN_HOST   = 2,
    /* The socket was unexpectedly closed, possibly by the peer. */
    SS_MSG_STATUS_FAILED_SOCKET_CLOSED                     = 3,
    /* Not enough system or network resources to complete the operation. */
    SS_MSG_STATUS_FAILED_NO_RESOURCES                      = 4,
    /* The message being sent or received exceeds the allowable maximum size. */
    SS_MSG_STATUS_FAILED_BUF_LEN_TOO_LARGE           = 5,
    /* The message being sent or received is smaller than the allowable minimum size. */
    SS_MSG_STATUS_FAILED_BUF_LEN_TOO_SMALL           = 6,
};

/**
 * @brief Base of the buffer to send and receive.
 */
struct Msg {
    std::string m_msg; /* Buffer of content received or sent */
    eSSMsgStatus m_status; /* Result of sent or received a buffer */

public:
    /**
     * @brief Init with null.
     */
    Msg();

    /**
     * @param [in] msg Contents of the buffer to initialize.
     */
    explicit Msg(const std::string& msg);

#if CURRENT_CXX_VERSION >= 201103L
    /**
     * @param [in] msg Contents of the buffer to initialize.
     */
    explicit Msg(std::string&& msg);
#endif //CURRENT_CXX_VERSION >= 201103L

    /**
     * @param [in] pMsg Char pointer for buffer.
     * @param [in] len Buffer length of pStr.
     */
    Msg(const char* pMsg, kani_buflen_t len);
};

inline
Msg::Msg() :
    m_status(SS_MSG_STATUS_UNKNOWN) { }

inline
Msg::Msg(const std::string& msg) :
    m_msg(msg),
    m_status(SS_MSG_STATUS_UNKNOWN) { }

#if CURRENT_CXX_VERSION >= 201103L
inline
Msg::Msg(std::string&& msg) :
    m_msg(std::move(msg)),
    m_status(SS_MSG_STATUS_UNKNOWN) { }
#endif //CURRENT_CXX_VERSION >= 201103L

inline
Msg::Msg(const char* const pMsg, const kani_buflen_t len) :
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
    /**
     * @brief Init with null.
     */
    SendMsg();

    /**
    * @param [in] msg Buffer to send.
    */
    explicit SendMsg(const std::string& msg);

#if CURRENT_CXX_VERSION >= 201103L
    /**
     * @param [in] msg Buffer to send.
     */
    explicit SendMsg(std::string&& msg);
#endif //CURRENT_CXX_VERSION >= 201103L

    /**
    * @param [in] pMsg Char pointer for buffer to send.
    * @param [in] len Buffer length of pStr.
    */
    SendMsg(const char* pMsg, kani_buflen_t len);
};

inline
SendMsg::SendMsg() :
    m_sentLen(0) { }

inline
SendMsg::SendMsg(const std::string& msg) :
    Msg(msg),
    m_sentLen(0) { }

#if CURRENT_CXX_VERSION >= 201103L
inline
SendMsg::SendMsg(std::string&& msg) :
    Msg(std::move(msg)),
    m_sentLen(0) { }
#endif //CURRENT_CXX_VERSION >= 201103L

inline
SendMsg::SendMsg(const char* const pMsg, const kani_buflen_t len) :
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
    const kani_buflen_t m_maxLen; /* Receivable buffer length. Must be less than 'KANI_MAX_SIZE'. */

public:
    /**
     * @return Receivable buffer length
     */
    kani_buflen_t get_max_len() const;

public:
    /**
     * @param [in] maxLen Maximum buffer length that can be received.
     */
    explicit RecvMsg(kani_buflen_t maxLen = KANI_DEFAULT_MAX_MSG_LEN);
};

inline
kani_buflen_t RecvMsg::get_max_len() const {
    return m_maxLen;
}

inline
RecvMsg::RecvMsg(const kani_buflen_t maxLen) :
    m_recvLen(0),
    m_maxLen(maxLen) { }

// ======================= S T R U C T =======================
// ===    SocketInfo
// ======================= S T R U C T =======================

/**
 * @brief Using when initializing a socket.
 */
struct SocketInfo {
    std::string m_node; /* Host name or ip address. */
    std::string m_service; /* Service name or port number. */
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
enum eSSStartResult : int32_t {
    /* Started successfully. */
    SS_START_RESULT_SUCCESS                                  = 0,
    /* Failed to start because already started. */
    SS_START_RESULT_FAILED_ALREADY_STARTED = 1,
    /* Socket creation failed. */
    SS_START_RESULT_FAILED_CREATE_SOCKET      = 2,
    /* Socket binding failed. */
    SS_START_RESULT_FAILED_BIND_SOCKET          = 3,
    /* Failed to listen on the socket. */
    SS_START_RESULT_FAILED_LISTEN_SOCKET      = 4,
};

// ======================== C L A S S ========================
// ===    ISocket
// ======================== C L A S S ========================

class ISocket {
public:
    /**
     * @brief This should initialize the socket and start the server or client.
     *
     * @return Returns whether the socket was initialized and the server or client started successfully.
     */
    virtual eSSStartResult start() = 0;

    /**
     * @brief This should shut down the server or client and close the socket.
     */
    virtual void stop() = 0;

public:
    virtual ~ISocket();
};

inline
ISocket::~ISocket() { }

// ======================== C L A S S ========================
// ===    Socket
// ======================== C L A S S ========================

/**
 * @brief Server and Client Interface.
 *              Helps initialize the socket.
 */
class Socket : public ISocket {
public:
    /**
     * @brief Before calling start(), you should call this method to ensure that the socket can be initialized.
     *
     * @return Returns true when the socket is ready to be initialized.
     */
    bool is_valid() const;
protected:
    /**
     * @brief Initialize addrinfo with the supplied args.
     * <br>It starts working after zerofilling addrinfo, so if you want to insert additional hints into addrinfo, you should do so after calling this method.
     *
     * @param [in, out] hints addrinfo to use as hints.
     * @param [in] sockHints SocketHints of the options to reference when initializing addrinfo.
     */
    static void get_addrinfo_hints(addrinfo& hints, SocketHints sockHints);

    /**
     * @brief Initialize the m_pAddrInfo by referencing SocketInfo and SocketHints.
     *
     * @param [in] info
     * @param [in] sockHints
     * @return Returns false if the information provided in SocketInfo or SocketHints is invalid.
     */
    bool parse_socketinfo(const SocketInfo& info, SocketHints sockHints);

public:
    Socket();

    /**
     * @brief Close the socket and free m_pAddrInfo.
     */
    virtual ~Socket();
protected:
    bool m_isValid;                   /* Is socket can be initialized? */
    kani_socket_t m_socket; /* Socket on the server or client */
    addrinfo* m_pAddrInfo;  /* Required when creating a socket */
private:
#ifdef _WIN32
    WSAData m_wsaData; /* Required on win32 only */
#endif //_WIN32
#ifdef KANITERU_ASYNC_SOCKET_INCLUDED
    friend async_socket::ISocket;
#endif //KANITERU_ASYNC_SOCKET_INCLUDED
};

inline
bool Socket::is_valid() const {
    return m_isValid;
}

inline
void Socket::get_addrinfo_hints(addrinfo& hints, const SocketHints sockHints) {
    memset(&hints, 0, sizeof(hints));

    if (sockHints.m_isTcp) {
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
    } else {
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
    }

    if (sockHints.m_isServer) {
        hints.ai_flags = AI_PASSIVE;
    }
}

inline
bool Socket::parse_socketinfo(const SocketInfo& info, const SocketHints sockHints) {
    addrinfo hints;
    get_addrinfo_hints(hints, sockHints);
    hints.ai_family = info.m_protocolFamily;
    return getaddrinfo(info.m_node.c_str(), info.m_service.c_str(), &hints, &m_pAddrInfo) == 0;
}

inline
Socket::Socket() :
    m_isValid(true),
    m_socket(KANI_INVALID_SOCKET),
    m_pAddrInfo(KANI_NULLPTR) {

#ifdef _WIN32
    if (WSAStartup(MAKEWORD(2, 2), &m_wsaData) != 0) {
        m_isValid = false;
    }
#endif
}

inline
Socket::~Socket() {
    if (m_socket != KANI_INVALID_SOCKET) {
        KANI_CLOSE_SOCKET(m_socket);
    }

    if (m_pAddrInfo) {
        freeaddrinfo(m_pAddrInfo);
        m_pAddrInfo = KANI_NULLPTR;
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
    virtual bool send_msg(SendMsg* pMsg, kani_flag_t flag) const = 0;

    /**
     * @brief This should receive a message from the server.
     *
     * @param [in, out] pMsg
     * @param [in] flag Flags for recv() or recvfrom().
     * @return Returns true if the message was successfully received from the server.
     */
    virtual bool recv_msg(RecvMsg* pMsg, kani_flag_t flag) const = 0;

    virtual ~IClient();
};

inline
IClient::~IClient() { }

// ======================== C L A S S ========================
// ===    NetAddr
// ======================== C L A S S ========================

class NetAddr {
public:
    /**
     * @return Return parse was success.
     */
    bool is_valid() const;

    /**
     * @return Returns sockaddr.
     */
    const sockaddr_storage& get_sockaddr() const;

    /**
     * @return Returns host str (like ip, domain).
     */
    KANI_STRVIEW get_host() const;

    /**
     * @return Returns service str (like port).
     */
    KANI_STRVIEW get_service() const;
protected:
    /**
     * @brief Parse sockaddr to host and service str.
     *
     * @param [in] flags getnameinfo() flags.
     * @return Returns true if parse successful.
     */
    bool parse_addr(kani_flag_t flags);

public:
    /**
     * @brief Init with null.
     */
    NetAddr();

    /**
     * @param [in] sock Target socket. The Socket must be not closed.
     * @param [in] flags getnameinfo() flags.
     */
    explicit NetAddr(kani_socket_t sock, kani_flag_t flags = NI_NUMERICHOST | NI_NUMERICSERV);

    /**
     * @param [in] ss Target sockaddr.
     * @param [in] flags getnameinfo() flags.
     */
    explicit NetAddr(const sockaddr_storage& ss, kani_flag_t flags = NI_NUMERICHOST | NI_NUMERICSERV);

    /**
     * @param [in] ai Target addrinfo.
     * @param [in] flags getnameinfo() flags.
     */
    explicit NetAddr(const addrinfo& ai, kani_flag_t flags = NI_NUMERICHOST | NI_NUMERICSERV);

    /**
     * @param [in] other Other NetAddr.
     * @param [in] flags getnameinfo() flags.
     */
    explicit NetAddr(const NetAddr& other, kani_flag_t flags = NI_NUMERICHOST | NI_NUMERICSERV);
protected:
    bool m_isValid;
    std::string m_host;
    std::string m_service;
    sockaddr_storage m_addr;
};

inline
bool NetAddr::is_valid() const {
    return m_isValid;
}

inline
const sockaddr_storage& NetAddr::get_sockaddr() const {
    return m_addr;
}

inline
KANI_STRVIEW NetAddr::get_host() const {
    return m_host;
}

inline
KANI_STRVIEW NetAddr::get_service() const {
    return m_service;
}

inline
bool NetAddr::parse_addr(const kani_flag_t flags) {
    char szHost[NI_MAXHOST + 1];
    char szService[NI_MAXSERV + 1];
    memset(szHost, '\0', sizeof(szHost));
    memset(szService, '\0', sizeof(szService));

    const bool result = getnameinfo(reinterpret_cast<sockaddr*>(&m_addr), sizeof(m_addr), szHost, NI_MAXHOST, szService, NI_MAXSERV, flags) == 0;

    if (result) {
        m_host.assign(szHost);
        m_service.assign(szService);
    }

    return result;
}

inline
NetAddr::NetAddr() :
    m_isValid(false) { }

inline
NetAddr::NetAddr(const kani_socket_t sock, const kani_flag_t flags) :
    m_isValid(false) {

    kani_socklen_t len = sizeof(m_addr);

    if (getsockname(sock, reinterpret_cast<sockaddr*>(&m_addr), &len) == 0) {
        m_isValid = this->parse_addr(flags);
    }
}

inline
NetAddr::NetAddr(const sockaddr_storage& ss, const kani_flag_t flags) :
    m_addr(ss) {

    m_isValid = this->parse_addr(flags);
}

inline
NetAddr::NetAddr(const addrinfo& ai, const kani_flag_t flags) {
    memset(&m_addr, 0, sizeof(m_addr));
    memcpy(&m_addr, ai.ai_addr, ai.ai_addrlen);
    m_isValid = this->parse_addr(flags);
}

inline
NetAddr::NetAddr(const NetAddr& other, const kani_flag_t flags) :
    m_addr(other.m_addr) {

    m_isValid = this->parse_addr(flags);
}

// ======================== C L A S S ========================
// ===    MsgHelper
// ======================== C L A S S ========================

/**
 * @brief Helper class for message processing operations, including validation and handling message results.
 */
class MsgHelper {
public:
    /**
     * @brief Validates the buffer size of the given message.
     *
     * @param [in, out] pMsg A pointer to the SendMsg object whose buffer size needs to be validated.
     * @return True if the buffer size is valid, false otherwise.
     */
    static bool validate_buf_size(SendMsg* pMsg);

    /**
     * @brief Validates the buffer size of the max receivable.
     *
     * @param [in, out] pMsg Pointer to the received message to validate.
     * @return True if the buffer size is valid, false otherwise.
     */
    static bool validate_buf_size(RecvMsg* pMsg);

    /**
     * @brief Handles the result of a message after it has been sent.
     *
     * @param [in, out] pMsg A pointer to the message object that was sent.
     * @return Returns true if sent successful.
     */
    static bool handle_msg_result(SendMsg* pMsg);

    /**
     * @brief Handles the result of a received message.
     *
     * @param [in, out] pMsg A constant pointer to the received message object to be processed.
     * @return Returns true if received successful.
     */
    static bool handle_msg_result(RecvMsg* pMsg);

    /**
     * @brief Alloc char buf.
     *
     * @param [in] len Char len.
     * @return Returns nullptr if alloc failed otherwise, Returns char ptr.
     *
     * @code
     * size_t len = 1024;
     * char* pBuf = alloc_recv_buf(len);
     *
     * if (pBuf) { ... }
     * @endcode
     */
    static char* alloc_recv_buf(size_t len) noexcept;

    /**
     * @brief Free the allocated char buf.
     *
     * @param [in, out] p Char ptr.
     *
     * @code
     * char* pBuf = alloc_recv_buf(...);
     * ...
     * free_recv_buf(pBuf);
     * @endcode
     */
    static void free_recv_buf(char* p) noexcept;
private:
    /**
     * @brief Validates the buffer size to ensure it meets required constraints.
     *
     * @param [in, out] pMsg A msg ptr.
     * @param [in] len The length of the buffer to be validated.
     * @return Returns -1 = Size is too small.
     *      Returns 0 = Valid size.
     *      Returns 1 = Size is too big.
     */
    static uint8_t validate_buf_size(Msg* pMsg, size_t len);

    /**
     * @brief Handles the result of a message processing operation.
     *
     * @param [in, out] pMsg Pointer to the message being processed.
     * @param [in] len The length of the message.
     * @return Returns true if len bigger than KANI_INVALID_BUF_LEN.
     */
    static bool handle_msg_result(Msg* pMsg, kani_buflen_t len);
};

inline
bool MsgHelper::validate_buf_size(SendMsg* const pMsg) {
    return MsgHelper::validate_buf_size(pMsg, pMsg->m_msg.length()) == 0;
}

inline
bool MsgHelper::validate_buf_size(RecvMsg* const pMsg) {
    return MsgHelper::validate_buf_size(pMsg, pMsg->get_max_len()) == 0;
}

inline
bool MsgHelper::handle_msg_result(SendMsg* const pMsg) {
    return MsgHelper::handle_msg_result(pMsg, pMsg->m_sentLen);
}

inline
bool MsgHelper::handle_msg_result(RecvMsg* const pMsg) {
    return MsgHelper::handle_msg_result(pMsg, pMsg->m_recvLen);
}

inline
char* MsgHelper::alloc_recv_buf(const size_t len) noexcept {
    char* pRes = KANI_NULLPTR;
    const size_t realLen = len + 1;

    try {
        pRes = new char[realLen];
    }
    catch (const std::bad_alloc&) {
        return KANI_NULLPTR;
    }

    memset(pRes, '\0', realLen);
    return pRes;
}

inline
void MsgHelper::free_recv_buf(char* p) noexcept {
    if (p) {
        delete[] p;
    }
}

inline
uint8_t MsgHelper::validate_buf_size(Msg* const pMsg, const size_t len) {
    if (len <= KANI_INVALID_BUF_LEN) {
        pMsg->m_status = SS_MSG_STATUS_FAILED_BUF_LEN_TOO_SMALL;
        return -1;
    }

    if (len > KANI_MAX_BUF_LEN || len == KANI_MAX_SIZE) {
        pMsg->m_status = SS_MSG_STATUS_FAILED_BUF_LEN_TOO_LARGE;
        return 1;
    }

    return 0;
}

inline
bool MsgHelper::handle_msg_result(Msg* const pMsg, const kani_buflen_t len) {
    if (len > KANI_INVALID_BUF_LEN) {
        pMsg->m_status = SS_MSG_STATUS_SUCCESS;
        return true;
    }

    if (len == KANI_INVALID_BUF_LEN) {
        pMsg->m_status = SS_MSG_STATUS_FAILED_SOCKET_CLOSED;
        return false;
    }

    pMsg->m_status = SS_MSG_STATUS_FAILED;
    return false;
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
     * @param [in] socket Host or client socket.
     * @param [in, out] pMsg Msg ptr.
     * @param [in] flag Flags for send().
     * @return Returns true if the message was sent successfully.
     *
     * @code
     * kani_socket_t socket = ...;
     * SendMsg msg(...);
     *
     * if (TcpMsgHelper::send_msg(socket, &msg, ...)) { ... }
     * @endcode
     */
    static bool send_msg(kani_socket_t socket, SendMsg* pMsg, kani_flag_t flag);

    /**
     * @brief Receive an incoming message from the socket.
     *
     * @param [in] socket Host or client socket.
     * @param [in, out] pMsg Msg ptr.
     * @param [in] flag Flags for recv().
     * @return Returns true if the message was received successfully.
     *
     * @code
     * kani_socket_t socket = ...;
     * RecvMsg msg(...);
     *
     * if (TcpMsgHelper::recv_msg(socket, &msg, ...)) { ... }
     * @endcode
     */
    static bool recv_msg(kani_socket_t socket, RecvMsg* pMsg, kani_flag_t flag);
};

inline
bool TcpMsgHelper::send_msg(const kani_socket_t socket, SendMsg* const pMsg, const kani_flag_t flag) {
    if (!pMsg || !MsgHelper::validate_buf_size(pMsg)) {
        return false;
    }

    const std::string& str = pMsg->m_msg;
    const size_t len = str.length();

    if (len > KANI_MAX_BUF_LEN) {
        pMsg->m_status = SS_MSG_STATUS_FAILED_BUF_LEN_TOO_LARGE;
        return false;
    }

    pMsg->m_sentLen = send(socket, str.c_str(), static_cast<kani_buflen_t>(len), flag);
    return MsgHelper::handle_msg_result(pMsg);
}

inline
bool TcpMsgHelper::recv_msg(const kani_socket_t socket, RecvMsg* const pMsg, const kani_flag_t flag) {
    if (!pMsg || !MsgHelper::validate_buf_size(pMsg)) {
        return false;
    }

    const kani_buflen_t maxLen = pMsg->get_max_len();
    char* pStr = MsgHelper::alloc_recv_buf(maxLen);

    if (!pStr) {
        pMsg->m_status = SS_MSG_STATUS_FAILED_NO_RESOURCES;
        return false;
    }

    pMsg->m_recvLen = recv(socket, pStr, maxLen, flag);

    const bool result = MsgHelper::handle_msg_result(pMsg);

    if (result) {
        pMsg->m_msg.assign(pStr, pMsg->m_recvLen);
    }

    MsgHelper::free_recv_buf(pStr);
    pStr = KANI_NULLPTR;
    return result;
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
     * @param [in] socket Host socket.
     * @param [in, out] pMsg Msg ptr.
     * @param [in] pAddr Target sockaddr.
     * @param [in] addrLen Len of target sockaddr
     * @param [in] flag Flags for sendto().
     * @return Returns true if the message was sent successfully.
     *
     * @code
     * kani_socket_t socket = ...;
     * SendMsg msg(...);
     * sockaddr_storage addr = ...;
     * kani_socklen_t addrLen = sizeof(addr);
     *
     * if (UdpMsgHelper::send_msg(socket, &msg, reinterpret_cast<sockaddr*>(&addr), addrLen, ...)) { ... }
     * @endcode
     */
    static bool send_msg(kani_socket_t socket, SendMsg* pMsg, const sockaddr* pAddr, kani_socklen_t addrLen, kani_flag_t flag);

    /**
     * @brief Send a message to the NetAddr.
     *
     * @param [in] socket Host socket.
     * @param [in, out] pMsg Msg ptr.
     * @param [in] pNetAddr Target NetAddr ptr.
     * @param [in] flag Flags for sendto().
     * @return Returns true if the message was sent successfully.
     *
     * @code
     * kani_socket_t socket = ...;
     * SendMsg msg(...);
     * NetAddr addr(...);
     *
     * if (UdpMsgHelper::send_msg(socket, &msg, &addr, ...)) { ... }
     * @endcode
     */
    static bool send_msg(kani_socket_t socket, SendMsg* pMsg, const NetAddr* pNetAddr, kani_flag_t flag);

    /**
     * @brief Receive an incoming message from the socket.
     *
     * @param [in] socket Host socket.
     * @param [in, out] pMsg Msg ptr.
     * @param [in, out, optional] pAddr Target sockaddr ptr.
     * @param [in, out, optional] pAddrLen Len of target sockaddr.
     * @param [in] flag Flags for recvfrom().
     * @return Returns true if the message was received successfully.
     *
     * @code
     * kani_socket_t socket = ...;
     * RecvMsg msg(...);
     * sockaddr_storage addr;
     * kani_socklen_t addrLen = sizeof(addr);
     *
     * if (UdpMsgHelper::recv_msg(socket, &msg, reinterpret_cast<sockaddr*>(&addr), &addrLen, ...)) { ... }
     * @endcode
     *
     * @code
     * if (UdpMsgHelper::recv_msg(socket, &msg, NULL, NULL, ...)) { ... }
     * @endcode
     */
    static bool recv_msg(kani_socket_t socket, RecvMsg* pMsg, sockaddr* pAddr, kani_socklen_t* pAddrLen, kani_flag_t flag);

    /**
     * @brief Receive an incoming message from the socket.
     *
     * @param [in] socket Host socket.
     * @param [in, out] pMsg Msg ptr.
     * @param [in, out, optional] pNetAddr Target NetAddr ptr.
     * @param [in] flag Flags for recvfrom().
     * @return Returns true if the message was received successfully.
     *
     * @code
     * kani_socket_t socket = ...;
     * RecvMsg msg(...);
     * NetAddr addr;
     *
     * if (UdpMsgHelper::recv_msg(socket, &msg, &addr, ...)) { ... }
     * @endcode
     *
     * @code
     * if (UdpMsgHelper::recv_msg(socket, &msg, NULL, ...)) { ... }
     * @endcode
     */
    static bool recv_msg(kani_socket_t socket, RecvMsg* pMsg, NetAddr* pNetAddr, kani_flag_t flag);
};

inline
bool UdpMsgHelper::send_msg(const kani_socket_t socket, SendMsg* const pMsg, const sockaddr* const pAddr, const kani_socklen_t addrLen, const kani_flag_t flag) {
    if (!pMsg || !pAddr || !MsgHelper::validate_buf_size(pMsg)) {
        return false;
    }

    const std::string& str = pMsg->m_msg;
    const size_t len = str.length();

    if (len > KANI_MAX_UDP_BUF_LEN) {
        pMsg->m_status = SS_MSG_STATUS_FAILED_BUF_LEN_TOO_LARGE;
        return false;
    }

    pMsg->m_sentLen = sendto(socket, str.c_str(), static_cast<kani_buflen_t>(len), flag, pAddr, addrLen);
    return MsgHelper::handle_msg_result(pMsg);
}

inline
bool UdpMsgHelper::send_msg(const kani_socket_t socket, SendMsg* const pMsg, const NetAddr* const pNetAddr, const kani_flag_t flag) {
    if (!pNetAddr) {
        return false;
    }

    sockaddr_storage addr = pNetAddr->get_sockaddr();
    const kani_socklen_t len = sizeof(addr);
    return UdpMsgHelper::send_msg(socket, pMsg, reinterpret_cast<sockaddr*>(&addr), len, flag);
}

inline
bool UdpMsgHelper::recv_msg(const kani_socket_t socket, RecvMsg* const pMsg, sockaddr* const pAddr, kani_socklen_t* const pAddrLen, const kani_flag_t flag) {
    if (!pMsg || !MsgHelper::validate_buf_size(pMsg)) {
        return false;
    }

    const kani_buflen_t maxLen = pMsg->get_max_len();
    char* pStr = MsgHelper::alloc_recv_buf(maxLen);

    if (!pStr) {
        pMsg->m_status = SS_MSG_STATUS_FAILED_NO_RESOURCES;
        return false;
    }

    pMsg->m_recvLen = recvfrom(socket, pStr, maxLen, flag, pAddr, pAddrLen);

    const bool result = MsgHelper::handle_msg_result(pMsg);

    if (result) {
        pMsg->m_msg.assign(pStr, pMsg->m_recvLen);
    }

    MsgHelper::free_recv_buf(pStr);
    pStr = KANI_NULLPTR;
    return result;
}

inline
bool UdpMsgHelper::recv_msg(const kani_socket_t socket, RecvMsg* const pMsg, NetAddr* const pNetAddr, const kani_flag_t flag) {
    if (!pNetAddr) {
        return UdpMsgHelper::recv_msg(socket, pMsg, KANI_NULLPTR, KANI_NULLPTR, flag);
    }

    sockaddr_storage addr;
    kani_socklen_t len = sizeof(addr);
    memset(&addr, 0, len);

    if (!UdpMsgHelper::recv_msg(socket, pMsg, reinterpret_cast<sockaddr*>(&addr), &len, flag)) {
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
     * @brief Get socket ID.
     * <br>Note: Before used TcpNetClient::close(), it always returns KANI_INVALID_SOCKET.
     *
    * @return Returns the socket ID.
    */
    kani_socket_t get_socket() const;

    /**
     * @return Returns true if the client socket is closed.
     */
    bool is_closed() const;

    /**
     * @brief Close the client socket.
     */
    void close();

public:
    /**
     * @brief Init with null.
     */
    TcpNetClient();

    /**
     * @brief Init with null socket.
     *
     * @param [in] addr Target sockaddr.
     */
    explicit TcpNetClient(const sockaddr_storage& addr);

    /**
     * @param [in] socket Target socket.
     * @param [in] addr Target sockaddr.
     */
    TcpNetClient(kani_socket_t socket, const sockaddr_storage& addr);
protected:
    kani_socket_t m_socket;
};

inline
kani_socket_t TcpNetClient::get_socket() const {
    return m_socket;
}

inline
bool TcpNetClient::is_closed() const {
    return m_socket == KANI_INVALID_SOCKET;
}

inline
void TcpNetClient::close() {
    if (this->is_closed()) {
        return;
    }

    KANI_CLOSE_SOCKET(m_socket);
    m_socket = KANI_INVALID_SOCKET;
}

inline
TcpNetClient::TcpNetClient() :
    NetAddr(),
    m_socket(KANI_INVALID_SOCKET) { }

inline
TcpNetClient::TcpNetClient(const sockaddr_storage& addr) :
    NetAddr(addr),
    m_socket(KANI_INVALID_SOCKET) { }

inline
TcpNetClient::TcpNetClient(const kani_socket_t socket, const sockaddr_storage& addr) :
    NetAddr(addr),
    m_socket(socket) { }

// ======================= S T R U C T =======================
// ===    TcpServerSocketInfo
// ======================= S T R U C T =======================

/**
 * @brief Using when initializing TcpServer.
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
class TcpServer : public Socket {
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
    eSSStartResult start() override;

    /**
     * @brief Check for an incoming client to the server.
     *
     * @param [out] pClient
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
    bool wait_client(TcpNetClient* pClient) const;

    /**
     * @brief Sends a message to the client.
     *
     * @param [in] client Client socket.
     * @param [in, out] pMsg Msg ptr.
     * @param [in] flag Flags for send().
     * @return Returns true if sent successfully.
     *
     * @code
     * TcpServer server(...);
     * kani_socket_t fd = ...;
     * SendMsg msg(...);
     *
     * if (server.send_msg(fd, &msg, ...)) { ... }
     * @endcode
     */
    bool send_msg(kani_socket_t client, SendMsg* pMsg, kani_flag_t flag = 0) const;

    /**
     * @brief Sends a message to the client.
     *
     * @param [in] pClient Client ptr.
     * @param [in, out] pMsg Msg ptr.
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
    bool send_msg(const TcpNetClient* pClient, SendMsg* pMsg, kani_flag_t flag = 0) const;

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
    bool recv_msg(const TcpNetClient* pClient, RecvMsg* pMsg, kani_flag_t flag = 0) const;

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
    const int32_t m_backlog;
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

    if (bind(m_socket, m_pAddrInfo->ai_addr, static_cast<kani_socklen_t>(m_pAddrInfo->ai_addrlen)) == KANI_SOCKET_ERROR) {
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
bool TcpServer::wait_client(TcpNetClient* const pClient) const {
    if (!pClient) {
        return false;
    }

    sockaddr_storage addr;
    kani_socklen_t addrLen = sizeof(addr);
    memset(&addr, 0, sizeof(addr));

    const kani_socket_t socket = accept(m_socket, reinterpret_cast<sockaddr*>(&addr), &addrLen);

    if (socket == KANI_INVALID_SOCKET) {
        return false;
    }

    *pClient = TcpNetClient(socket, addr);
    return true;
}

inline bool TcpServer::send_msg(const kani_socket_t client, SendMsg* const pMsg, const kani_flag_t flag) const {
    if (!pMsg) {
        return false;
    }

    return TcpMsgHelper::send_msg(client, pMsg, flag);
}

inline
bool TcpServer::send_msg(const TcpNetClient* const pClient, SendMsg* const pMsg, const kani_flag_t flag) const {
    if (!pClient) {
        return false;
    }

    return this->send_msg(pClient->get_socket(), pMsg, flag);
}

inline
bool TcpServer::recv_msg(const TcpNetClient* const pClient, RecvMsg* const pMsg, const kani_flag_t flag) const {
    if (!pClient || !pMsg) {
        return false;
    }

    return TcpMsgHelper::recv_msg(pClient->get_socket(), pMsg, flag);
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
TcpServer::TcpServer(const TcpServerSocketInfo& info) :
    m_backlog(info.m_backlog) {

    if (!m_isValid) {
        return;
    }

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
class TcpClient : public Socket, public IClient {
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
    eSSStartResult start() override;

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
    bool connect() const;

    /**
     * @brief Send a message to the server.
     *
     * @param [in, out] pMsg
     * @param [in] flag Flags for send().
     * @return Returns true if the message was sent successfully.
     *
     * @code
     * TcpClient client(...);
     * SendMsg msg(...);
     *
     * if (client.send_msg(&msg, ...)) { ... }
     * @endcode
     */
    bool send_msg(SendMsg* pMsg, kani_flag_t flag = 0) const override;

    /**
     * @brief Receive a message from the server.
     *
     * @param [in, out] pMsg
     * @param [in] flag Flags for recv().
     * @return Returns true if the message was received successfully.
     *
     * @code
     * TcpClient client(...);
     * RecvMsg msg(...);
     *
     * if (client.recv_msg(&msg, ...)) { ... }
     * @endcode
     */
    bool recv_msg(RecvMsg* pMsg, kani_flag_t flag = 0) const override;

    /**
     * @brief Shutdown the client.
     *              If you want to reconnect to the server, you must call start() before calling connect().
     */
    void stop() override;

public:
    /**
     * @param [in] info
     */
    explicit TcpClient(const SocketInfo& info);
    ~TcpClient() override;
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
bool TcpClient::connect() const {
    return ::connect(m_socket, m_pAddrInfo->ai_addr, static_cast<kani_socklen_t>(m_pAddrInfo->ai_addrlen)) != KANI_SOCKET_ERROR;
}

inline
bool TcpClient::send_msg(SendMsg* const pMsg, const kani_flag_t flag) const {
    return TcpMsgHelper::send_msg(m_socket, pMsg, flag);
}

inline
bool TcpClient::recv_msg(RecvMsg* const pMsg, const kani_flag_t flag) const {
    return TcpMsgHelper::recv_msg(m_socket, pMsg, flag);
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
class UdpServer : public Socket {
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
    eSSStartResult start() override;

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
    bool send_msg(const NetAddr* pClient, SendMsg* pMsg, kani_flag_t flag = 0) const;

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
    bool recv_msg(NetAddr* pClient, RecvMsg* pMsg, kani_flag_t flag = 0) const;

    /**
     * @brief Shutdown the server.
     */
    void stop() override;

public:
    /**
     * @param [in] info
     */
    explicit UdpServer(const SocketInfo& info);
    ~UdpServer() override;
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

    if (bind(m_socket, m_pAddrInfo->ai_addr, static_cast<kani_socklen_t>(m_pAddrInfo->ai_addrlen)) == KANI_SOCKET_ERROR) {
        this->stop();
        return SS_START_RESULT_FAILED_BIND_SOCKET;
    }

    return SS_START_RESULT_SUCCESS;
}

inline
bool UdpServer::send_msg(const NetAddr* const pClient, SendMsg* const pMsg, const kani_flag_t flag) const {
    if (!pClient || !pMsg) {
        return false;
    }

    return UdpMsgHelper::send_msg(m_socket, pMsg, pClient, flag);
}

inline
bool UdpServer::recv_msg(NetAddr* const pClient, RecvMsg* const pMsg, const kani_flag_t flag) const {
    if (!pClient || !pMsg) {
        return false;
    }

    return UdpMsgHelper::recv_msg(m_socket, pMsg, pClient, flag);
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
class UdpClient : public Socket, public IClient {
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
    eSSStartResult start() override;

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
    bool send_msg(SendMsg* pMsg, kani_flag_t flag = 0) const override;

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
    bool recv_msg(RecvMsg* pMsg, kani_flag_t flag = 0) const override;

    /**
     * @brief Shutdown the client.
     *              If you want to receive or send messages again, you should call start().
     */
    void stop() override;

public:
    explicit UdpClient(const SocketInfo& info);
    ~UdpClient() override;
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
bool UdpClient::send_msg(SendMsg* const pMsg, const kani_flag_t flag) const {
    return UdpMsgHelper::send_msg(m_socket, pMsg, m_pAddrInfo->ai_addr, static_cast<kani_socklen_t>(m_pAddrInfo->ai_addrlen), flag);
}

inline
bool UdpClient::recv_msg(RecvMsg* const pMsg, const kani_flag_t flag) const {
    NetAddr sender;

    if (!UdpMsgHelper::recv_msg(m_socket, pMsg, &sender, flag)) {
        return false;
    }

    if (m_netServer.get_host() != sender.get_host() || m_netServer.get_service() != sender.get_service()) {
        pMsg->m_status = SS_MSG_STATUS_SUCCESS_FROM_UNKNOWN_HOST;
        return false;
    }

    return true;
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
} //namespace simple_socket
} //namespace kani


#endif //KANITERU_SIMPLE_SOCKET_HPP
