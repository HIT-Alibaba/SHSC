#ifndef _SHSC_IMAGE_IMAGE_SERVER_
#define _SHSC_IMAGE_IMAGE_SERVER_

#include "network/async_server.h"
#include "network/event_pool.h"
#include "network/async_client.h"

#include "share/mutex.h"

#include "image/ssl_server.h"

#include <map>
#include <vector>

namespace shsc {

  class ImageServer: public CustomSSLServer {
    public:
      ImageServer(EventPool* event_pool, const InetAddress& bindaddr);

      bool AddImage(const InetAddress& address, const std::string& filename, 
          const std::string& image, 
          const std::string& checksum);

      std::vector<std::string> QueryFiles();
      
      bool QueryImage(const std::string& filename, InetAddress& address);

      void OnReadCompletion(const AsyncConnectionPtr& conn, const char* buffer);

    private:

      bool CheckHash(std::string file, std::string checksum);

      //  <files, file node: ip:port>
      std::map<std::string, InetAddress> files_;


      Mutex mutex_;

      // no copying allowed
      void operator=(const ImageServer&);
      ImageServer(const ImageServer&);
  };

} // namespace shsc

#endif //_SHSC_IMAGE_IMAGE_SERVER_
