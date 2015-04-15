#ifndef _SHSC_NETWORK_CALLBACKS_H_
#define _SHSC_NETWORK_CALLBACKS_H_

#include <boost/function.hpp>
#include <boost/shared_ptr.hpp>

namespace shsc {

class Buffer;
class AsyncConnection;

typedef boost::shared_ptr<AsyncConnection> AsyncConnectionPtr;

typedef boost::function<void (const AsyncConnectionPtr&)> ConnectionCallback;
typedef boost::function<void (const AsyncConnectionPtr&)> WriteCompletionCallback;
typedef boost::function<void (const AsyncConnectionPtr&, Buffer*)> ReadCompletionCallback;
typedef boost::function<void (const AsyncConnectionPtr&)> CloseCallback;

} // namespace shsc

#endif // _SHSC_NETWORK_CALLBACKS_H_
