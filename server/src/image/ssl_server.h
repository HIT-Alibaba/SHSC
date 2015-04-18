#ifndef _SHSC_IMAGE_SSL_SERVER_H_
#define _SHSC_IMAGE_SSL_SERVER_H_

#include "network/async_server.h"
#include "network/event_pool.h"
#include "network/async_client.h"
#include "image/rsa.h"
#include "rapidjson/document.h"

#include <map>
#include <vector>
#include <cstdint>

using namespace rapidjson;

namespace shsc {

  struct ClientInfo {
    int32_t random1;
    int32_t random2;
    unsigned char* client_pubkey;
    std::string master_secret;

    // ?
    InetAddress address;
  };


  class CustomSSLServer {

    public:
    
      CustomSSLServer(EventPool* event_pool, const InetAddress& bindaddr);
      void Start();

      bool IsClientHello(const char* msg, const InetAddress& address);
      void ServerHello(const AsyncConnectionPtr& conn, ClientInfo* client);
      
      bool ConfirmACK(const char* msg, ClientInfo* client);      

      void ServerFinish(const AsyncConnectionPtr& conn, ClientInfo* client);

      void SSLWrite(const AsyncConnectionPtr& conn, const char* msg);
      const char* SSLRead(const ClientInfo* client,  const std::string& enc_msg);

      void OnSSLReadCompletion(const AsyncConnectionPtr& conn, Buffer* buffer);

      virtual void OnReadCompletion(const AsyncConnectionPtr& conn, const char* buffer);
      void OnConnection(const AsyncConnectionPtr& conn);
      void OnConnectionClose(const AsyncConnectionPtr& conn);

      void iatouc(const rapidjson::Value& array, unsigned char* epk);

    protected:

      ShscRSA* rsa_;
      KeyPair* keypair_;
      
      int random1; // send to client in server_hello

      EventPool* event_pool_;
      AsyncServer async_server_;

      Mutex mutex_;

      const char* iv = "0123456789";

      std::map<InetAddress, ClientInfo*> half_connections_;
      std::map<InetAddress, ClientInfo*> connections_;

      // no copying allowed
      void operator=(const CustomSSLServer&);
      CustomSSLServer(const CustomSSLServer&);
  };

} // namespace shsc

#endif //_SHSC_IMGAE_SSL_SERVER_H_
