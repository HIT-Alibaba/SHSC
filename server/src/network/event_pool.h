#ifndef _SHSC_NETWORK_EVENTPOOL_H_
#define _SHSC_NETWORK_EVENTPOOL_H_

#include "network/epoller.h"
#include "network/channel.h"
#include "network/socket.h"
#include "share/threadpool.h"
#include <boost/noncopyable.hpp>
#include <boost/ptr_container/ptr_vector.hpp>

namespace shsc {

class EventPool : boost::noncopyable {
  public:
    typedef ThreadPool::Job Job;
    typedef EPoller::ChannelList ChannelList;

    EventPool(int pollers, int backends);
    ~EventPool();

    void Run();
    void Stop();

    void WakeUp();

    void AttachChannel(Channel* channel);
    void DetachChannel(Channel* channel);
    void DisableChannel(Channel* channel);

    // choose the first thread by default
    void PostJob(const Job& job, int which = 0);
    void PostJob(const Job& job, const Channel& channel);

    void PollWrapper(int which);

  private:
    volatile int running_;
    const int num_pollers_;
    const int num_backends_;

    boost::ptr_vector<EPoller> pollers_;
    boost::ptr_vector<Socket> wakeup_socks_;
    boost::ptr_vector<Channel> wakeup_chans_;
    ThreadPool poller_handler_;
    ThreadPool backend_handler_;
};

} // namespace shsc

#endif // _SHSC_NETWORK_EVENTPOOL_H_
