#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <io.h>
  #include <direct.h>
  #include <sys/stat.h>
  #include <fcntl.h>

  using socket_t = SOCKET;
  inline constexpr socket_t kInvalidSocket = INVALID_SOCKET;
  #define SHUT_WR SD_SEND
  #define SHUT_RD SD_RECEIVE
  #define SHUT_RDWR SD_BOTH
#else
  #include <sys/socket.h>
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <poll.h>
  #include <fcntl.h>
  #include <unistd.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <errno.h>

  using socket_t = int;
  inline constexpr socket_t kInvalidSocket = -1;
#endif

namespace hooh {

inline bool init_networking() {
#ifdef _WIN32
    WSADATA wsa;
    return (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
#else
    return true;
#endif
}

inline void cleanup_networking() {
#ifdef _WIN32
    WSACleanup();
#endif
}

inline void close_socket(socket_t s) {
    if (s != kInvalidSocket) {
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
    }
}

inline int shutdown_write(socket_t s) {
#ifdef _WIN32
    return shutdown(s, SD_SEND);
#else
    return shutdown(s, SHUT_WR);
#endif
}

inline int poll_sockets(struct pollfd* fds, unsigned long nfds, int timeout_ms) {
#ifdef _WIN32
    return WSAPoll(fds, nfds, timeout_ms);
#else
    return poll(fds, nfds, timeout_ms);
#endif
}

inline bool set_socket_nonblocking(socket_t s, bool nonblocking) {
#ifdef _WIN32
    u_long mode = nonblocking ? 1 : 0;
    return (ioctlsocket(s, FIONBIO, &mode) == 0);
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0) return false;
    flags = nonblocking ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    return (fcntl(s, F_SETFL, flags) == 0);
#endif
}

inline bool socket_would_block() {
#ifdef _WIN32
    int err = WSAGetLastError();
    return (err == WSAEWOULDBLOCK);
#else
    return (errno == EAGAIN || errno == EWOULDBLOCK);
#endif
}

} // namespace hooh
