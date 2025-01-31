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
#include <vector>

#if CURRENT_CXX_VERSION < 201103L
    #include <stdint.h>
    #include <assert.h>
#else
    #include <cstdint>
    #include <cassert>
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
#define KANI_MAX_IP_LEN                        INET6_ADDRSTRLEN
#define KANI_MAX_PORT_LEN                  5
#define KANI_INVALID_BUF_LEN             0
#define KANI_DEFAULT_MAX_MSG_LEN 65535

#ifdef _WIN32
    #define KANI_INVALID_SOCKET         INVALID_SOCKET
    #define KANI_SOCKET_ERROR            SOCKET_ERROR
    #define KANI_CLOSE_SOCKET(SOCK) closesocket(SOCK);
#else
    #define KANI_INVALID_SOCKET        (-1)
    #define KANI_SOCKET_ERROR            (-1)
    #define KANI_CLOSE_SOCKET(SOCK) close(SOCK);
#endif //_WIN32

#if CURRENT_CXX_VERSION < 201103L
    #define override
    #define KANI_NULLPTR NULL
#else
    #define KANI_NULLPTR nullptr
#endif //CURRENT_CXX_VERSION < 201103L

#ifdef KANITERU_ASYNC_SOCKET_INCLUDED
    #define KANITERU_SIMPLE_SOCKET_CHECKED_ASYNC_SOCKET_INCLUDE
#endif //KANITERU_ASYNC_SOCKET_INCLUDED

namespace kani {

// ======================= S T R U C T =======================
// ===    Msg
// ======================= S T R U C T =======================

/**
 * @brief Using get status when buffer is sent or received.
 *              [ SS = SimpleSocket ]
 */
enum eSSMsgStatus {
    /* Received failed, to know the cause, using SocketErrTracker */
    SS_MSG_STATUS_UNKNOWN                                              = -1,
    /* Sent or received success. */
    SS_MSG_STATUS_SUCCESS                                                 = 0,
    /* In the udp client, received msg success but sender isn't the server we want. */
    SS_MSG_STATUS_SUCCESS_FROM_UNKNOWN_HOST   = 1,
    /* The operation was blocked due to system-level restrictions or permissions. */
    SS_MSG_STATUS_FAILED_BLOCKED                                   = 2,
    /* The socket was unexpectedly closed, possibly by the peer. */
    SS_MSG_STATUS_FAILED_SOCKET_CLOSED                     = 3,
    /* Attempted operation on a socket that is not currently connected. */
    SS_MSG_STATUS_FAILED_NOT_CONNECTED                   = 4,
    /* The connection was lost during the operation. */
    SS_MSG_STATUS_FAILED_CONNECTION_LOST               = 5,
    /* The network is unreachable or unavailable. */
    SS_MSG_STATUS_FAILED_NETWORK_DOWN                   = 6,
    /* The connection or action was explicitly rejected by the peer. */
    SS_MSG_STATUS_FAILED_REFUSED                                   = 7,
    /* Insufficient system or network resources to complete the operation. */
    SS_MSG_STATUS_FAILED_NO_RESOURCES                      = 8,
    /* Failed to initialize buffer due to insufficient memory. */
    SS_MSG_STATUS_FAILED_MAX_BUF_LEN_TOO_LARGE  = 9,
    /* Buf size too small (like 0). */
    SS_MSG_STATUS_FAILED_MAX_BUF_LEN_TOO_SMALL = 10,
    /* The message being sent or received exceeds the allowable maximum size. */
    SS_MSG_STATUS_FAILED_MSG_TOO_LARGE                   = 11,
    /* The message being sent or received is smaller than the allowable minimum size. */
    SS_MSG_STATUS_FAILED_MSG_TOO_SMALL                   = 12,
    /* Failed due to integrity verification error in TcpSafeMsgHelper. */
    SS_MSG_STATUS_FAILED_INTEGRITY_CHECK                 = 13
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
    m_sentLen(0) {


}
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

// ======================== C L A S S ========================
// ===    SocketErrTracker
// ======================== C L A S S ========================

/**
 * @brief Represents various socket error statuses.
 */
enum eSSSocketErrStatus {
    /* No error occurred; the operation succeeded (e.g., data sent/received successfully). */
    SS_SOCKET_ERR_STATUS_NO_ERROR = -1,
    /* The operation was successfully completed without issues. */
    SS_SOCKET_ERR_STATUS_SUCCESS = 0,
    /* The connection was reset by the peer (e.g., the remote socket was closed abruptly). */
    SS_SOCKET_ERR_STATUS_CONNECTION_RESET = 1,
    /* The operation timed out (e.g., no response within the expected time frame). */
    SS_SOCKET_ERR_STATUS_CONNECTION_TIMEOUT = 2,
    /* The operation would have blocked on a non-blocking socket. */
    SS_SOCKET_ERR_STATUS_WOULD_BLOCK = 3,
    /* The operation should be retried due to an interrupted system call or temporary issue. */
    SS_SOCKET_ERR_STATUS_TRY_AGAIN = 4,
    /* The network is unavailable, likely due to a connectivity issue. */
    SS_SOCKET_ERR_STATUS_NETWORK_DOWN = 5,
    /* Unknown or unhandled socket error occurred. */
    SS_SOCKET_ERR_STATUS_UNKNOWN = 6,
    /* The socket is invalid or not properly initialized. */
    SS_SOCKET_ERR_STATUS_INVALID_SOCKET = 7,
    /* Too many open files/sockets on the system (limits exceeded). */
    SS_SOCKET_ERR_STATUS_TOO_MANY_OPEN_SOCKETS = 8,
    /* The address is already in use (e.g., binding to an address/port that is in use). */
    SS_SOCKET_ERR_STATUS_ADDRESS_IN_USE = 9,
    /* The requested address is not available (e.g., invalid or unavailable for binding). */
    SS_SOCKET_ERR_STATUS_ADDRESS_NOT_AVAILABLE = 10,
    /* Permission denied for the requested socket operation (e.g., binding to a privileged port). */
    SS_SOCKET_ERR_STATUS_PERMISSION_DENIED = 11,
    /* The remote host could not be reached (e.g., no route to host). */
    SS_SOCKET_ERR_STATUS_HOST_UNREACHABLE = 12,
    /* General network-related error indicating the connection was dropped. */
    SS_SOCKET_ERR_STATUS_CONNECTION_ABORTED = 13,
    /* The specified socket operation is not supported by the protocol. */
    SS_SOCKET_ERR_STATUS_OPERATION_NOT_SUPPORTED = 14,
    /* Protocol errors (e.g., a protocol violation occurred). */
    SS_SOCKET_ERR_STATUS_PROTOCOL_ERROR = 15,
    /* Resources are temporarily unavailable (e.g., buffers or memory). */
    SS_SOCKET_ERR_STATUS_RESOURCE_TEMPORARILY_UNAVAILABLE = 16,
    /* Message size is too large to be processed by the underlying network protocol. */
    SS_SOCKET_ERR_STATUS_MESSAGE_TOO_LARGE = 17,
    /* The socket is not connected (e.g., attempted send/receive on an unconnected socket). */
    SS_SOCKET_ERR_STATUS_SOCKET_NOT_CONNECTED = 18,
    /* The connection was closed by the remote side (graceful shutdown). */
    SS_SOCKET_ERR_STATUS_CONNECTION_CLOSED = 19,
    /* The socket operation failed because it was already in progress. */
    SS_SOCKET_ERR_STATUS_OPERATION_ALREADY_IN_PROGRESS = 20,
        /* The transport endpoint is already connected to a remote socket (duplicate connect attempt). */
    SS_SOCKET_ERR_STATUS_ALREADY_CONNECTED = 21,
    /* A blocking operation is currently in progress (e.g., a non-blocking socket is used improperly). */
    SS_SOCKET_ERR_STATUS_IN_PROGRESS = 22,
    /* The network is unreachable (e.g., due to a misconfigured router or firewall issue). */
    SS_SOCKET_ERR_STATUS_NETWORK_UNREACHABLE = 23,
    /* There's a broken pipe (e.g., writing to a socket that has been closed on the other end). */
    SS_SOCKET_ERR_STATUS_BROKEN_PIPE = 24,
    /* Packet was truncated or data was lost in transit. */
    SS_SOCKET_ERR_STATUS_PACKET_TRUNCATED = 25,
    /* The requested socket type is not supported by the protocol. */
    SS_SOCKET_ERR_STATUS_SOCKET_TYPE_NOT_SUPPORTED = 26,
    /* The protocol family is unsupported for the requested operation (e.g., IPv6 vs IPv4 conflict). */
    SS_SOCKET_ERR_STATUS_PROTOCOL_FAMILY_UNSUPPORTED = 27,
    /* The buffer on the socket is full (e.g., write buffer overflow). */
    SS_SOCKET_ERR_STATUS_BUFFER_FULL = 28,
    /* The operation was canceled (e.g., due to socket closure or application interruption). */
    SS_SOCKET_ERR_STATUS_OPERATION_CANCELED = 29,
    /* The remote side is not responding (e.g., keepalive or ping timeout). */
    SS_SOCKET_ERR_STATUS_REMOTE_NOT_RESPONDING = 30,
    /* A timeout occurred while establishing the connection (e.g., connect timeout). */
    SS_SOCKET_ERR_STATUS_CONNECTION_ESTABLISH_TIMEOUT = 31,
    /* Invalid argument was passed (e.g., misconfigured socket options). */
    SS_SOCKET_ERR_STATUS_INVALID_ARGUMENT = 32,
    /* Socket shut down for read/write operations (e.g., due to a manual shutdown). */
    SS_SOCKET_ERR_STATUS_SOCKET_SHUTDOWN = 33,
    /* Hostname resolution failed (e.g., DNS errors such as a "host not found"). */
    SS_SOCKET_ERR_STATUS_HOSTNAME_RESOLUTION_FAILED = 34,
    /* The connection was refused by the remote host (e.g., the host is not accepting connections). */
    SS_SOCKET_ERR_STATUS_CONNECTION_REFUSED = 35,
    /* The remote peer abruptly closed the connection while data was still being exchanged. */
    SS_SOCKET_ERR_STATUS_REMOTE_DISCONNECTED = 36,
    /* Failed to bind the socket (possibly due to invalid parameters or unavailable ports). */
    SS_SOCKET_ERR_STATUS_BIND_FAILED = 37,
    /* Failed to listen for incoming connections on the given socket. */
    SS_SOCKET_ERR_STATUS_LISTEN_FAILED = 38,
    /* The socket has been unexpectedly closed or invalidated. */
    SS_SOCKET_ERR_STATUS_SOCKET_CLOSED_UNEXPECTEDLY = 39,
    /* The system ran out of memory while handling the socket. */
    SS_SOCKET_ERR_STATUS_OUT_OF_MEMORY = 40,
    /* Unsupported address family (e.g., using AF_UNIX on a system that only supports AF_INET). */
    SS_SOCKET_ERR_STATUS_ADDRESS_FAMILY_UNSUPPORTED = 41,
    /* Protocol is not available or supported on this host system. */
    SS_SOCKET_ERR_STATUS_PROTOCOL_UNAVAILABLE = 42,
    /* The connection was reset due to an RST (reset) packet being received. */
    SS_SOCKET_ERR_STATUS_RST_PACKET_RECEIVED = 43
};

/**
 * @brief Tracks and manages socket error codes and their corresponding statuses.
 */
class SocketErrTracker {
    /**
     * @brief Retrieves the error code being tracked in the SocketErrTracker.
     * @return The error code currently stored in the tracker.
     */
public:
    int32_t get_err_code() const;

    /**
     * @brief Converts the current error tracking state into a corresponding error status.
     * @return The resulting error status derived from the tracked error state.
     */
    eSSSocketErrStatus to_err_status() const;

    /**
     * @brief Converts the current socket error tracking state into a corresponding message status representation.
     * @return The message status derived from the tracked socket error state.
     */
    eSSMsgStatus to_msg_status() const;

public:
    /**
     * @brief Constructor for the SocketErrTracker class, initializes the error tracking for socket operations.
     * @return An instance of SocketErrTracker with default initialization.
     */
    SocketErrTracker();

    /**
     * @brief Destructor for the SocketErrTracker class, responsible for cleaning up resources
     *        and performing necessary teardown operations associated with the error tracking.
     */
    ~SocketErrTracker();

private:
    int32_t m_lastErr; /* Stores the last error code encountered during operation. */
};

inline
int32_t SocketErrTracker::get_err_code() const {
    return m_lastErr;
}

inline
eSSSocketErrStatus SocketErrTracker::to_err_status() const {
#ifdef _WIN32
    switch (m_lastErr) {
        case 0:
            return SS_SOCKET_ERR_STATUS_NO_ERROR;
        case WSAECONNRESET:
            return SS_SOCKET_ERR_STATUS_CONNECTION_RESET;
        case WSAETIMEDOUT:
            return SS_SOCKET_ERR_STATUS_CONNECTION_TIMEOUT;
        case WSAEWOULDBLOCK:
            return SS_SOCKET_ERR_STATUS_WOULD_BLOCK;
        case WSAEINTR:
            return SS_SOCKET_ERR_STATUS_TRY_AGAIN;
        case WSAENETDOWN:
            return SS_SOCKET_ERR_STATUS_NETWORK_DOWN;
        case WSAEADDRINUSE:
            return SS_SOCKET_ERR_STATUS_ADDRESS_IN_USE;
        case WSAEADDRNOTAVAIL:
            return SS_SOCKET_ERR_STATUS_ADDRESS_NOT_AVAILABLE;
        case WSAEACCES:
            return SS_SOCKET_ERR_STATUS_PERMISSION_DENIED;
        case WSAEHOSTUNREACH:
            return SS_SOCKET_ERR_STATUS_HOST_UNREACHABLE;
        case WSAECONNABORTED:
            return SS_SOCKET_ERR_STATUS_CONNECTION_ABORTED;
        case WSAEOPNOTSUPP:
            return SS_SOCKET_ERR_STATUS_OPERATION_NOT_SUPPORTED;
        case WSAEPROTONOSUPPORT:
        case WSAESOCKTNOSUPPORT:
            return SS_SOCKET_ERR_STATUS_PROTOCOL_ERROR;
        case WSAEMSGSIZE:
            return SS_SOCKET_ERR_STATUS_MESSAGE_TOO_LARGE;
        case WSAENOTCONN:
            return SS_SOCKET_ERR_STATUS_SOCKET_NOT_CONNECTED;
        case WSAEISCONN:
            return SS_SOCKET_ERR_STATUS_ALREADY_CONNECTED;
        case WSAENETUNREACH:
            return SS_SOCKET_ERR_STATUS_NETWORK_UNREACHABLE;
        case WSAECANCELLED:
            return SS_SOCKET_ERR_STATUS_OPERATION_CANCELED;
        case WSAEINPROGRESS:
            return SS_SOCKET_ERR_STATUS_IN_PROGRESS;
        case WSAECONNREFUSED:
            return SS_SOCKET_ERR_STATUS_CONNECTION_REFUSED;
        case WSAESHUTDOWN:
            return SS_SOCKET_ERR_STATUS_SOCKET_SHUTDOWN;
        case WSAENOTSOCK:
        case WSATYPE_NOT_FOUND:
            return SS_SOCKET_ERR_STATUS_INVALID_SOCKET;
        case WSAEMFILE:
            return SS_SOCKET_ERR_STATUS_TOO_MANY_OPEN_SOCKETS;
        case WSAEAFNOSUPPORT:
            return SS_SOCKET_ERR_STATUS_ADDRESS_FAMILY_UNSUPPORTED;
        case WSAENOBUFS:
        case WSA_NOT_ENOUGH_MEMORY:
            return SS_SOCKET_ERR_STATUS_OUT_OF_MEMORY;

        default:
            return SS_SOCKET_ERR_STATUS_UNKNOWN;
    }
#else
    switch (m_lastErr) {
        case 0:
            return SS_SOCKET_ERR_STATUS_NO_ERROR;
        case ECONNRESET:
            return SS_SOCKET_ERR_STATUS_CONNECTION_RESET;
        case ETIMEDOUT:
            return SS_SOCKET_ERR_STATUS_CONNECTION_TIMEOUT;
        case EWOULDBLOCK:
        case EAGAIN:
            return SS_SOCKET_ERR_STATUS_WOULD_BLOCK;
        case EINTR:
            return SS_SOCKET_ERR_STATUS_TRY_AGAIN;
        case ENETDOWN:
            return SS_SOCKET_ERR_STATUS_NETWORK_DOWN;
        case EADDRINUSE:
            return SS_SOCKET_ERR_STATUS_ADDRESS_IN_USE;
        case EADDRNOTAVAIL:
            return SS_SOCKET_ERR_STATUS_ADDRESS_NOT_AVAILABLE;
        case EACCES:
            return SS_SOCKET_ERR_STATUS_PERMISSION_DENIED;
        case EHOSTUNREACH:
            return SS_SOCKET_ERR_STATUS_HOST_UNREACHABLE;
        case ECONNABORTED:
            return SS_SOCKET_ERR_STATUS_CONNECTION_ABORTED;
        case EOPNOTSUPP:
            return SS_SOCKET_ERR_STATUS_OPERATION_NOT_SUPPORTED;
        case EMSGSIZE:
            return SS_SOCKET_ERR_STATUS_MESSAGE_TOO_LARGE;
        case ENOTCONN:
            return SS_SOCKET_ERR_STATUS_SOCKET_NOT_CONNECTED;
        case EISCONN:
            return SS_SOCKET_ERR_STATUS_ALREADY_CONNECTED;
        case ENETUNREACH:
            return SS_SOCKET_ERR_STATUS_NETWORK_UNREACHABLE;
        case ECANCELED:
            return SS_SOCKET_ERR_STATUS_OPERATION_CANCELED;
        case EINPROGRESS:
            return SS_SOCKET_ERR_STATUS_IN_PROGRESS;
        case ECONNREFUSED:
            return SS_SOCKET_ERR_STATUS_CONNECTION_REFUSED;
        case ESHUTDOWN:
            return SS_SOCKET_ERR_STATUS_SOCKET_SHUTDOWN;
        case ENOTSOCK:
            return SS_SOCKET_ERR_STATUS_INVALID_SOCKET;
        case EMFILE:
            return SS_SOCKET_ERR_STATUS_TOO_MANY_OPEN_SOCKETS;
        case EAFNOSUPPORT:
            return SS_SOCKET_ERR_STATUS_ADDRESS_FAMILY_UNSUPPORTED;
        case ENOBUFS:
        case ENOMEM:
            return SS_SOCKET_ERR_STATUS_OUT_OF_MEMORY;
        default:
            return SS_SOCKET_ERR_STATUS_UNKNOWN;
    }
#endif //_WIN32
}

inline
eSSMsgStatus SocketErrTracker::to_msg_status() const {
    switch (to_err_status()) {
        case SS_SOCKET_ERR_STATUS_NO_ERROR:
        case SS_SOCKET_ERR_STATUS_SUCCESS:
            return SS_MSG_STATUS_SUCCESS;

        case SS_SOCKET_ERR_STATUS_CONNECTION_RESET:
        case SS_SOCKET_ERR_STATUS_CONNECTION_ABORTED:
        case SS_SOCKET_ERR_STATUS_CONNECTION_TIMEOUT:
        case SS_SOCKET_ERR_STATUS_REMOTE_NOT_RESPONDING:
        case SS_SOCKET_ERR_STATUS_CONNECTION_ESTABLISH_TIMEOUT:
        case SS_SOCKET_ERR_STATUS_RST_PACKET_RECEIVED:
            return SS_MSG_STATUS_FAILED_CONNECTION_LOST;

        case SS_SOCKET_ERR_STATUS_NETWORK_DOWN:
        case SS_SOCKET_ERR_STATUS_NETWORK_UNREACHABLE:
        case SS_SOCKET_ERR_STATUS_HOST_UNREACHABLE:
            return SS_MSG_STATUS_FAILED_NETWORK_DOWN;

        case SS_SOCKET_ERR_STATUS_CONNECTION_REFUSED:
        case SS_SOCKET_ERR_STATUS_REMOTE_DISCONNECTED:
            return SS_MSG_STATUS_FAILED_REFUSED;

        case SS_SOCKET_ERR_STATUS_OUT_OF_MEMORY:
        case SS_SOCKET_ERR_STATUS_RESOURCE_TEMPORARILY_UNAVAILABLE:
            return SS_MSG_STATUS_FAILED_NO_RESOURCES;

        case SS_SOCKET_ERR_STATUS_MESSAGE_TOO_LARGE:
            return SS_MSG_STATUS_FAILED_MSG_TOO_LARGE;

        case SS_SOCKET_ERR_STATUS_SOCKET_NOT_CONNECTED:
            return SS_MSG_STATUS_FAILED_NOT_CONNECTED;

        case SS_SOCKET_ERR_STATUS_SOCKET_CLOSED_UNEXPECTEDLY:
        case SS_SOCKET_ERR_STATUS_BROKEN_PIPE:
            return SS_MSG_STATUS_FAILED_SOCKET_CLOSED;

        default:
            return SS_MSG_STATUS_UNKNOWN;
    }
}

inline
SocketErrTracker::SocketErrTracker() :
#ifdef _WIN32
    m_lastErr(WSAGetLastError()) {
#else
    m_lastErr(errno) {
#endif //_WIN32
}

inline
SocketErrTracker::~SocketErrTracker() { }

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
enum eSSStartResult {
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

#ifdef KANITERU_ASYNC_SOCKET_INCLUDED
namespace async_socket {
    class IAsyncSocket;
}
#endif //KANITERU_ASYNC_SOCKET_INCLUDED

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
    bool is_valid() const;

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
protected:
    /**
     * @brief Initialize addrinfo with the supplied args.
     *              It starts working after zerofilling addrinfo, so if you want to insert additional hints into addrinfo, you should do so after calling this method.
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
    ISocket();

    /**
     * @brief Close the socket and free m_pAddrInfo.
     */
    virtual ~ISocket();
protected:
    bool m_isValid; /* Is socket can be initialized? */
    kani_socket_t m_socket; /* Socket on the server or client */
    addrinfo* m_pAddrInfo; /* Required when creating a socket */
private:
#ifdef _WIN32
    WSAData m_wsaData; /* Required on win32 only */
#endif //_WIN32
#ifdef KANITERU_ASYNC_SOCKET_INCLUDED
    friend async_socket::IAsyncSocket;
#endif //KANITERU_ASYNC_SOCKET_INCLUDED
};

inline
bool ISocket::is_valid() const {
    return m_isValid;
}

inline
void ISocket::get_addrinfo_hints(addrinfo& hints, const SocketHints sockHints) {
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
bool ISocket::parse_socketinfo(const SocketInfo& info, const SocketHints sockHints) {
    addrinfo hints;
    get_addrinfo_hints(hints, sockHints);

    hints.ai_family = info.m_protocolFamily;

    return getaddrinfo(info.m_node.c_str(), info.m_service.c_str(), &hints, &m_pAddrInfo) == 0;
}

inline
ISocket::ISocket() :
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
ISocket::~ISocket() {
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
     * @return Returns ip address.
     */
    const std::string& get_ip() const;

    /**
     * @return Returns port.
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
    bool parse_addr(kani_flag_t flags = NI_NUMERICHOST | NI_NUMERICSERV);

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
bool NetAddr::parse_addr(const kani_flag_t flags) {
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

private:
    /**
     * @brief Validates the buffer size to ensure it meets required constraints.
     *
     * @param [in] len The length of the buffer to be validated.
     * @return Returns -1 = Size is too small.
     *      Returns 0 = Valid size.
     *      Returns 1 = Size is too big.
     */
    static uint8_t validate_buf_size(size_t len);

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
    const uint8_t valid = MsgHelper::validate_buf_size(pMsg->m_msg.length());

    if (valid == -1) {
        pMsg->m_status = SS_MSG_STATUS_FAILED_MSG_TOO_SMALL;
        return false;
    }

    if (valid == 1) {
        pMsg->m_status = SS_MSG_STATUS_FAILED_MSG_TOO_LARGE;
        return false;
    }

    return true;
}

inline
bool MsgHelper::validate_buf_size(RecvMsg* const pMsg) {
    const uint8_t valid = MsgHelper::validate_buf_size(pMsg->get_max_len());

    if (valid == -1) {
        pMsg->m_status = SS_MSG_STATUS_FAILED_MAX_BUF_LEN_TOO_SMALL;
        return false;
    }

    if (valid == 1) {
        pMsg->m_status = SS_MSG_STATUS_FAILED_MAX_BUF_LEN_TOO_LARGE;
        return false;
    }

    return true;
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
uint8_t MsgHelper::validate_buf_size(const size_t len) {
    if (len <= KANI_INVALID_BUF_LEN) {
        return -1;
    }

    if (len > KANI_MAX_BUF_LEN || len == KANI_MAX_SIZE) {
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

    pMsg->m_status = SocketErrTracker().to_msg_status();
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
     * @param [in] socket
     * @param [in, out] pMsg
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
     * @param [in] socket
     * @param [in, out] pMsg
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
    pMsg->m_sentLen = send(socket, str.c_str(), str.length(), flag);
    return MsgHelper::handle_msg_result(pMsg);
}

inline
bool TcpMsgHelper::recv_msg(const kani_socket_t socket, RecvMsg* const pMsg, const kani_flag_t flag) {
    if (!pMsg || !MsgHelper::validate_buf_size(pMsg)) {
        return false;
    }

    char* pStr = KANI_NULLPTR;
    const kani_buflen_t maxLen = pMsg->get_max_len();

    try {
        pStr = new char[maxLen + 1];
    }
    catch (const std::bad_alloc&) {
        pMsg->m_status = SS_MSG_STATUS_FAILED_MAX_BUF_LEN_TOO_LARGE;
        return false;
    }

    memset(pStr, '\0', maxLen + 1);
    pMsg->m_recvLen = recv(socket, pStr, maxLen, flag);

    const bool result = MsgHelper::handle_msg_result(pMsg);

    if (result) {
        pMsg->m_msg.assign(pStr, pMsg->m_recvLen);
    }

    delete[] pStr;
    pStr = KANI_NULLPTR;
    return result;
}

// ======================= S T R U C T =======================
// ===    TcpMsgHdr
// ======================= S T R U C T =======================

/**
 * @brief Represents the header structure for a TCP message.
 *
 * This struct provides a simple way to define the layout of a TCP message header
 * for communication and validation purposes, including start and end magic numbers,
 * message length, and a checksum value.
 */
#pragma pack(push, 1)
struct TcpMsgHdr {
    typedef uint32_t magic_num_t;

    magic_num_t   m_hdrStart;  /* Magic number indicating the start of the header. */
    kani_buflen_t m_len;            /* Length of the msg body (in bytes) */
    uint64_t          m_checksum; /* Checksum value calculated over the message content. */
    magic_num_t   m_hdrEnd;     /* Magic number indicating the end of the header. */

    static const magic_num_t HDR_START_MAGIC_NUM = 0xF250131FA; /* Start magic num. */
    static const magic_num_t HDR_END_MAGIC_NUM     = 0xF131052FB; /* End magic num. */
};
#pragma pack(pop)

// ======================= S T R U C T =======================
// ===    TcpSafeMsgHelper
// ======================= S T R U C T =======================

/**
 * @brief Provides utility functions for safe message handling over TCP
 */
class TcpSafeMsgHelper {
public:
    /**
     * @brief Sends a message over a TCP socket with specific safety mechanisms.
     *
     * This function constructs a message with necessary headers and data checksum,
     * encapsulates it within a buffer, and transmits it over the given socket.
     * The message's status is updated upon successful transmission.
     *
     * @param [in] socket The TCP socket descriptor to send the message through.
     * @param [in, out] pMsg Pointer to the SendMsg object containing the message data to be sent.
     * @param [in] flag Additional flags that specify the sending behavior.
     * @return Returns true if the message was successfully sent.
     */
    static bool send_msg(kani_socket_t socket, SendMsg* pMsg, kani_flag_t flag);

    /**
     * @brief Receives a message from the given socket and validates its integrity.
     *
     * This function reads data from the provided socket, verifies its headers, length, and checksum,
     * and then assigns the message body to the provided RecvMsg object. If any validation fails,
     * the function sets the appropriate status in the RecvMsg object and returns false.
     *
     * @param [in] socket The socket from which the message will be received.
     * @param [in, out] pMsg A pointer to a RecvMsg object that will store the received message and its status.
     * @param [in] flag A flag indicating message reception options or behavior.
     * @return Returns true if the message was successfully received and passed all integrity checks.
     */
    static bool recv_msg(kani_socket_t socket, RecvMsg* pMsg, kani_flag_t flag);

    /**
     * @brief Sends data over a TCP connection in a safe and controlled manner.
     *
     * This method repeatedly sends data until the entire buffer is transmitted.
     * It uses a helper to send individual messages while updating the message status.
     *
     * @param [in] socket The socket identifier used to send the data.
     * @param [in] pBuf Pointer to the buffer containing the data to be sent.
     * @param [in] bufLen Length of the buffer to be transmitted.
     * @param [in, out] pMsg Pointer to a SendMsg object that tracks the status and progress of the transmission.
     * @param [in] flag Configuration flags for sending the message.
     * @return Returns true if the entire buffer is sent successfully.
     */
    static bool send_data(kani_socket_t socket, const char* pBuf, size_t bufLen, SendMsg* pMsg, kani_flag_t flag);

    /**
     * @brief Receives data from a specified socket and stores it in the provided buffer.
     *
     * @param [in] socket The socket descriptor from which the data is received.
     * @param [in] pBuf Pointer to the buffer where the received data will be stored.
     * @param [in] bufLen The length of the buffer, indicating the maximum data to be received.
     * @param [in, out] pMsg Pointer to a RecvMsg object to store message-related information.
     * @param [in] flag Flags to define the behavior during data reception.
     * @return Returns true if the data is successfully received and stored into the buffer.
     */
    static bool recv_data(kani_socket_t socket, char* pBuf, size_t bufLen, RecvMsg* pMsg, kani_flag_t flag);


    /**
     * @brief Computes the checksum for the given data.
     *
     * @param data The input data for which the checksum needs to be calculated.
     * @param length The length of the data array.
     * @return The computed checksum value as an uint64_t.
     */
    static uint64_t calc_checksum(const char* pBuf, uint64_t len);
};

inline
bool TcpSafeMsgHelper::send_msg(const kani_socket_t socket, SendMsg* const pMsg, const kani_flag_t flag) {
    if (!pMsg) {
        return false;
    }

    const std::string& str = pMsg->m_msg;
    const size_t lenStr = str.length();

    std::vector<char> sendBuffer(sizeof(TcpMsgHdr) + lenStr);

    TcpMsgHdr hdr;
    hdr.m_hdrStart = TcpMsgHdr::HDR_START_MAGIC_NUM;
    hdr.m_len = lenStr;
    hdr.m_checksum = calc_checksum(str.c_str(), lenStr);
    hdr.m_hdrEnd = TcpMsgHdr::HDR_END_MAGIC_NUM;

    memcpy(sendBuffer.data(), &hdr, sizeof(TcpMsgHdr));
    memcpy(sendBuffer.data() + sizeof(TcpMsgHdr), str.data(), lenStr);

    return TcpSafeMsgHelper::send_data(socket, sendBuffer.data(), sendBuffer.size(), pMsg, flag);
}

inline
bool TcpSafeMsgHelper::recv_msg(const kani_socket_t socket, RecvMsg* const pMsg, const kani_flag_t flag) {
    if (!pMsg) {
        return false;
    }

    TcpMsgHdr hdr;

    if (!TcpSafeMsgHelper::recv_data(socket, reinterpret_cast<char*>(&hdr), sizeof(TcpMsgHdr), pMsg, flag)) {
        return false;
    }

    if (hdr.m_hdrStart != TcpMsgHdr::HDR_START_MAGIC_NUM || hdr.m_hdrEnd != TcpMsgHdr::HDR_END_MAGIC_NUM) {
        pMsg->m_status = SS_MSG_STATUS_FAILED_INTEGRITY_CHECK;
        return false;
    }

    std::vector<char> bodyBuf(hdr.m_len);

    if (!TcpSafeMsgHelper::recv_data(socket, bodyBuf.data(), hdr.m_len, pMsg, flag)) {
        return false;
    }

    if (hdr.m_checksum != calc_checksum(bodyBuf.data(), bodyBuf.size())) {
        pMsg->m_status = SS_MSG_STATUS_FAILED_INTEGRITY_CHECK;
        return false;
    }

    pMsg->m_msg.assign(bodyBuf.begin(), bodyBuf.end());
    return true;
}

inline
bool TcpSafeMsgHelper::send_data(const kani_socket_t socket, const char* const pBuf, const size_t bufLen, SendMsg* const pMsg, const kani_flag_t flag) {
    size_t totalSentLen = 0;

    while (totalSentLen < bufLen) {
        const size_t remainingLen = bufLen - totalSentLen;

        SendMsg msg(pBuf + totalSentLen, remainingLen);

        if (!TcpMsgHelper::send_msg(socket, &msg, flag)) {
            pMsg->m_status = msg.m_status;
            return false;
        }

        totalSentLen += msg.m_sentLen;
    }

    pMsg->m_sentLen = totalSentLen;
    pMsg->m_status = SS_MSG_STATUS_SUCCESS;
    return true;
}

inline
bool TcpSafeMsgHelper::recv_data(const kani_socket_t socket, char* const pBuf, const size_t bufLen, RecvMsg* const pMsg, const kani_flag_t flag) {
    const size_t maxChunkLen = pMsg->get_max_len();
    size_t totalRecvLen = 0;

    while (totalRecvLen < bufLen) {
        const size_t remainingLen = bufLen - totalRecvLen;
        const size_t chunkLen = (remainingLen > maxChunkLen) ? maxChunkLen : remainingLen;

        RecvMsg msg(chunkLen);

        if (!TcpMsgHelper::recv_msg(socket, &msg, flag)) {
            pMsg->m_status = msg.m_status;
            return false;
        }

        memcpy(pBuf + totalRecvLen, msg.m_msg.data(), msg.m_recvLen);
        totalRecvLen += msg.m_recvLen;
    }

    pMsg->m_recvLen = totalRecvLen;
    pMsg->m_status = SS_MSG_STATUS_SUCCESS;
    return true;
}

inline
uint64_t TcpSafeMsgHelper::calc_checksum(const char* const pBuf, const uint64_t len) {
    if (!pBuf || len == 0) {
        return 0;
    }

    const uint64_t blockSize = sizeof(uint64_t);
    uint64_t           checksum = 0;

    const uint8_t* pSrc = reinterpret_cast<const uint8_t*>(pBuf);

    uint64_t i = 0;
    for (; i + blockSize <= len; i += blockSize) {
        uint64_t block = 0;
        memcpy(&block, pSrc + i, blockSize);
        checksum ^= block;
    }

    for (; i < len; ++i) {
        checksum ^= static_cast<uint8_t>(pSrc[i]);
    }

    return checksum;
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
     * @param [in] socket
     * @param [in, out] pMsg
     * @param [in] pAddr
     * @param [in] addrLen
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
     * @param [in] socket
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
     * if (UdpMsgHelper::send_msg(socket, &msg, &addr, ...)) { ... }
     * @endcode
     */
    static bool send_msg(kani_socket_t socket, SendMsg* pMsg, const NetAddr* pNetAddr, kani_flag_t flag);

    /**
     * @brief Receive an incoming message from the socket.
     *
     * @param [in] socket
     * @param [in, out] pMsg
     * @param [out, optional] pAddr
     * @param [in, out, optional] pAddrLen
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
     * @param [in] socket
     * @param [in, out] pMsg
     * @param [out, optional] pNetAddr
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
    pMsg->m_sentLen = sendto(socket, str.c_str(), str.length(), flag, pAddr, addrLen);
    return MsgHelper::handle_msg_result(pMsg);
}

inline
bool UdpMsgHelper::send_msg(const kani_socket_t socket, SendMsg* const pMsg, const NetAddr* const pNetAddr, const kani_flag_t flag) {
    if (!pNetAddr) {
        return false;
    }

    sockaddr_storage addr = pNetAddr->get_addr();
    const kani_socklen_t len = sizeof(addr);
    return UdpMsgHelper::send_msg(socket, pMsg, reinterpret_cast<sockaddr*>(&addr), len, flag);
}

inline
bool UdpMsgHelper::recv_msg(const kani_socket_t socket, RecvMsg* const pMsg, sockaddr* const pAddr, kani_socklen_t* const pAddrLen, const kani_flag_t flag) {
    if (!pMsg || !MsgHelper::validate_buf_size(pMsg)) {
        return false;
    }

    const size_t maxLen = pMsg->get_max_len();
    char* pStr = KANI_NULLPTR;

    try {
        pStr = new char[maxLen + 1];
    }
    catch (const std::bad_alloc&) {
        pMsg->m_status = SS_MSG_STATUS_FAILED_MAX_BUF_LEN_TOO_LARGE;
        return false;
    }

    memset(pStr, '\0', maxLen + 1);
    pMsg->m_recvLen = recvfrom(socket, pStr, maxLen, flag, pAddr, pAddrLen);

    const bool result = MsgHelper::handle_msg_result(pMsg);

    if (result) {
        pMsg->m_msg.assign(pStr, pMsg->m_recvLen);
    }

    delete[] pStr;
    pStr = KANI_NULLPTR;
    return result;
}

inline
bool UdpMsgHelper::recv_msg(const kani_socket_t socket, RecvMsg* const pMsg, NetAddr* const pNetAddr, const kani_flag_t flag) {
    if (!pNetAddr) {
        return recv_msg(socket, pMsg, KANI_NULLPTR, KANI_NULLPTR, flag);
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
    TcpNetClient();

    /**
     * @param [in] addr
     */
    explicit TcpNetClient(const sockaddr_storage& addr);

    /**
     * @param [in] socket
     * @param [in] addr
     */
    TcpNetClient(kani_socket_t socket, const sockaddr_storage& addr);
private:
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

inline
bool TcpServer::send_msg(const TcpNetClient* const pClient, SendMsg* const pMsg, const kani_flag_t flag) const {
    if (!pClient || !pMsg) {
        return false;
    }

    return TcpMsgHelper::send_msg(pClient->get_socket(), pMsg, flag);
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
    bool send_msg(SendMsg* pMsg, kani_flag_t flag = 0) const override;

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
    return ::connect(m_socket, m_pAddrInfo->ai_addr, m_pAddrInfo->ai_addrlen) != KANI_SOCKET_ERROR;
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
     * @param [out, optional] pClient
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

    if (bind(m_socket, m_pAddrInfo->ai_addr, m_pAddrInfo->ai_addrlen) == KANI_SOCKET_ERROR) {
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
    return UdpMsgHelper::send_msg(m_socket, pMsg, m_pAddrInfo->ai_addr, m_pAddrInfo->ai_addrlen, flag);
}

inline
bool UdpClient::recv_msg(RecvMsg* const pMsg, const kani_flag_t flag) const {
    NetAddr sender;

    if (!UdpMsgHelper::recv_msg(m_socket, pMsg, &sender, flag)) {
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
} //namespace kani


#endif //KANITERU_SIMPLE_SOCKET_HPP
