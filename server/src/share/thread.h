#ifndef _SHSC_SHARE_THREAD_H_
#define _SHSC_SHARE_THREAD_H_

#include <boost/function.hpp>
#include <boost/noncopyable.hpp>
#include <pthread.h>

namespace shsc {

class Thread : boost::noncopyable {
  public:
    typedef boost::function<void()> BGWorker;

    explicit Thread(const BGWorker& worker);
    ~Thread();

    void Start();
    void Join();

    static int SelfId();

  private:
    bool started_;
    bool joined_;
    pthread_t pid_;
    BGWorker worker_; 
};

} // namespace shsc

#endif // _SHSC_SHARE_THREAD_H_
