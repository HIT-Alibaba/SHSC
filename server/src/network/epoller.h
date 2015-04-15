#ifndef _SHSC_NETWORK_EPOLLER_H_
#define _SHSC_NETWORK_EPOLLER_H_

#include <vector>
#include <map>
#include <sys/epoll.h>
#include <boost/noncopyable.hpp>

namespace shsc {

class Channel;
class EPoller : boost::noncopyable {
  public:
    typedef std::map<int, Channel*> ChannelMap;
    typedef std::vector<Channel*> ChannelList;
    typedef std::vector<struct epoll_event> EventList;

    EPoller();
    ~EPoller();

    void Poll(int timeout_ms, ChannelList* active_channels);
    void Close();
    void AttachChannel(Channel* channel);
    void DetachChannel(Channel* channel);
    void DisableChannel(Channel* channel);

  private:
    int epoll_fd_;
    ChannelMap channels_;
    EventList events_;
};

} // namespace shsc

#endif // _SHSC_NETWORK_EPOLLER_H_
