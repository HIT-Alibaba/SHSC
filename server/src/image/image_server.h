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
          const std::string& checksum,
          const std::string& image_checksum);

      std::vector<std::string> AllFiles();
      const char* vatoc(const std::vector<std::string> files);
      
      bool QueryImage(const std::string& filename, InetAddress& address);

      void OnReadCompletion(const AsyncConnectionPtr& conn, const char* buffer);

    private:

      bool CheckHash(std::string file, std::string checksum);

      //  <files, <file node: ip:port, image checksum> >
      std::map<std::string, std::pair<InetAddress, std::string> > files_;
      std::map<InetAddress, InetAddress> client_listen_map_;
      std::map<InetAddress, InetAddress> reverse_client_listen_map_;
      Mutex mutex_;

      // no copying allowed
      void operator=(const ImageServer&);
      ImageServer(const ImageServer&);
  };

} // namespace shsc

#endif //_SHSC_IMAGE_IMAGE_SERVER_
