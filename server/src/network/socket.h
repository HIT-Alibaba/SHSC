#ifndef _SHSC_NETWORK_SOCKET_H_
#define _SHSC_NETWORK_SOCKET_H_

#include <netinet/in.h>
#include <boost/noncopyable.hpp>

namespace shsc {

class InetAddress;

class Socket : boost::noncopyable {
  public:
    Socket(int fd);
    ~Socket();

    void Bind(const InetAddress& address);
    void Listen();
    int Accept(InetAddress* peer_address);

    void SetTcpNoDelay(bool opt);
    void SetReuseAddr(bool opt);
    void SetReusePort(bool opt);
    void SetKeepAlive(bool opt);

    int fd() const { return socket_fd_; }

    static int CreateNonblockingSocket();
    static int Connect(int fd, const struct sockaddr_in& addr);
    static struct sockaddr_in GetSocketName(int sockfd);
    static struct sockaddr_in GetLocalSockAddr(int sockfd);
    static struct sockaddr_in GetPeerSockAddr(int sockfd);

  private:
    const int socket_fd_;
};

} // namespace shsc

#endif // _SHSC_NETWORK_SOCKET_H_
