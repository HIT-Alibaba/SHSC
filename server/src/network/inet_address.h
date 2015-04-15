#ifndef _SHSC_NETWORK_INET_ADDRESS_H_
#define _SHSC_NETWORK_INET_ADDRESS_H_

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>
#include <string.h>


namespace shsc {

class InetAddress {
  public:
    typedef uint16_t Port;
    
    InetAddress(){}
    InetAddress(Port port);
    InetAddress(const std::string& ip, Port port);
    InetAddress(const sockaddr_in& inet_addr);

    friend bool operator < (const InetAddress& x, const InetAddress& y);

    void SetSockAddr(const sockaddr_in& inet_addr) {
        inet_addr_ = inet_addr;
    }

    uint16_t port() const {
        return ntohs(inet_addr_.sin_port);
    }

    std::string ip() const {
        char ip[32];
        ::inet_ntop(AF_INET, &inet_addr_.sin_addr, ip, sizeof(ip));
        return ip;
    }

    const struct sockaddr_in& sockaddr_in() const {
        return inet_addr_;
    }

  private:
    struct sockaddr_in inet_addr_;
};

inline bool operator < (const InetAddress& x, const InetAddress& y){
  int r = strncmp(x.ip().c_str(), y.ip().c_str(), 15);
  if(r != 0) return r > 0 ? false : true;
  return x.port() < y.port();

}

} // namespace shsc

#endif // _SHSC_NETWORK_INET_ADDRESS_H_
