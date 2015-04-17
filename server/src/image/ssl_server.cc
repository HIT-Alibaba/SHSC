#include "image/ssl_server.h"
#include "image/md5.h"
#include "image/rsa.h"

#include <rapidjson/document.h>
#include <boost/bind.hpp>

#include <utility>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

using namespace shsc;
using namespace rapidjson;


CustomSSLServer::CustomSSLServer(EventPool* event_pool, const InetAddress& bindaddr)
  : event_pool_(event_pool),
    async_server_(event_pool_, bindaddr)
{ 
  rsa_ = new ShscRSA(RSA_PKCS1_PADDING);
  keypair_ = rsa_->GetKeyPair();

  async_server_.SetReadCompletionCallback(boost::bind(
        &CustomSSLServer::OnSSLReadCompletion, this, _1, _2));

  async_server_.SetConnectionCallback(boost::bind(
        &CustomSSLServer::OnConnection, this, _1
        ));
  random1 = 1222222;
}

void CustomSSLServer::OnConnection(const AsyncConnectionPtr& conn){}

void CustomSSLServer::Start(){
  async_server_.Start();
}
 
/* Format of ServerHello massage:
 *
 * server random number : random2 uint64 ----> 8
 * length of key: sizeof size_t          ----> 8
 * length of cert checksum               ----> 8
 * server public key                     ----> length of key
 * server cert checksum                  ----> length of checksum
 * 
 *
 
void CustomSSLServer::ServerHello(const AsyncConnectionPtr& conn){
  size_t key_len = public_key.size();
  size_t cert_len = certificate_checksum.size();
  size_t random_len = sizeof(random2);
  size_t size = sizeof(size_t);

  char* msg = (char*)malloc(2*size+random_len+(key_len+cert_len));
  
  memcpy(msg, &random2, random_len);
  memcpy(msg+random_len, &key_len, size);
  memcpy(msg+random_len+size, &cert_len, size);
  memcpy(msg+random_len+2*size, public_key.c_str(), key_len);
  memcpy(msg+random_len+key_len+2*size, certificate_checksum.c_str(), cert_len);
  
  conn->Write(msg);
}

*/

/*
 * Format of server hello massage.
 * 
 * json:
 * {
 *  "body": {
 *    "pubkey": char*,
 *    "magic": random number 2
 *  },
 *  "checksum": checksum
 * }
 *
 */
void CustomSSLServer::ServerHello(const AsyncConnectionPtr& conn){
  
  int bodysize = strlen(reinterpret_cast<char*>(keypair_->public_key))/* public key */
      + 8 /*random number*/
      + 29;

  char* body = (char*)malloc(bodysize);
  int bc = sprintf(body, "\"body\":{\"pubkey\":\"%s\",\"magic\":%d}", keypair_->public_key, random1);
  if(bc == -1) ; // error;

  body[bodysize-1] = '\0';

  std::string checksum = md5(body);  

  char* msg = (char*) malloc (bodysize + 14 + checksum.size());
  
  int mc = sprintf(msg, "{%s,\"checksum\":\"%s\"}", body, checksum.c_str());
  if(mc == -1) ; // error;

  //LOG_TRACE("%s", msg);

  conn->Write(msg);

  free(msg);
  free(body);
}

/*
 * Format of client hello message:
 *
 * json :{ "type": "HELO", "magic": random number 1 }
 * 
 */
bool CustomSSLServer::IsClientHello(const char* msg, const InetAddress& address){
  Document document;
  document.Parse(msg);
  if(!document.HasMember("type")) return false;
  if(!document.HasMember("magic")) return false;
 
  if(strcmp(document["type"].GetString(), "HELO") != 0) return false;
  
  ClientInfo * client = new ClientInfo();
  client->random2 = document["magic"].GetInt();
  client->address = address;
  
  mutex_.Lock();
  half_connections_.insert(std::make_pair(address, client));
  
  mutex_.Unlock();

  return true;
}

void CustomSSLServer::iatouc(const Value& array, unsigned char* epk){
  for(rapidjson::SizeType i = 0; i < array.Size(); i++){
    epk[i] = array[i].GetInt();
  }
}

/*
 * Format of client confirm ack.
 *
 * json:
 * {
 *  "type":"ACK",
 *  "epk":encrpyted client public key.
 *  "length":client public key length
 *  "checksum":client key checksum
 * }
 *
 */
bool CustomSSLServer::ConfirmACK(const char* msg, ClientInfo* client){
  Document document;
  document.Parse(msg);

  if(!document.HasMember("type")) return false;
  if(!document.HasMember("epk")) return false;
  if(!document.HasMember("checksum")) return false;
  if(!document.HasMember("length")) return false;
  if(strcmp(document["type"].GetString(), "ACK") != 0) return false;
  
  const Value& jsonepk = document["epk"];
  std::vector<std::string> epk_array;
  
  int tempfd;

  for(rapidjson::SizeType i = 0; i < jsonepk.Size(); i++){
    unsigned char* epk = (unsigned char*)malloc(sizeof(unsigned char*)
        *jsonepk[i].Size());
    iatouc(jsonepk[i], epk);
    
    mutex_.Lock();
    tempfd = open("tempepk.key", O_WRONLY|O_CREAT, 0666);
    write(tempfd, epk, jsonepk[i].Size()); 
    

    FILE* pipe = popen("openssl rsautl -in tempepk.key -inkey private.pem -decrypt", "r");
    if(!pipe) return false; // error
    
    char buffer[128];
    std::string result = "";
    while(!feof(pipe)){
      if(fgets(buffer, 128, pipe) != NULL)
        result += buffer;
    }

    pclose(pipe);
    close(tempfd);

    epk_array.push_back(result);
    // ok.
    mutex_.Unlock();
  }
  
  std::string client_pubkey;

  for(size_t i = 0; i < epk_array.size(); i++){
    client_pubkey+=epk_array[i];
  }
   
  //LOG_TRACE("%s", client_pubkey.c_str());

  //const char* encrypted_client_pubkey = NULL; 
  //int PrivateDecrypt(unsigned char* enc_data, int sz, unsigned char* key, 
  //      unsigned char* decrypted);
  //unsigned char client_pub_key[2048 / 8];
  //rsa_->PrivateDecrypt(reinterpret_cast<const unsigned char*>(encrypted_client_pubkey)
  //    , document["length"].GetInt(),
  //  keypair_->private_key, client_pub_key);

  std::string epk_hash = md5(client_pubkey);

  if(strcmp(epk_hash.c_str(), document["checksum"].GetString()) != 0) return false;

  client->client_pubkey = (unsigned char*)malloc(sizeof(unsigned char)*client_pubkey.size());
  memcpy(client->client_pubkey, client_pubkey.c_str(), client_pubkey.size());
  
  mutex_.Lock();
  half_connections_.erase(half_connections_.find(client->address));
  connections_.insert(std::make_pair(client->address, client));
 
  mutex_.Unlock();

  return true;
}

/*
 * Last handshake message.
 * json:
 * {
 *  "type":"SFIN",
 *  "ms": the md5 of random1 | random2 | server public key | client public key
 * }
 *
 */
void CustomSSLServer::ServerFinish(const AsyncConnectionPtr& conn, ClientInfo* client){
  char *buffer = (char*)malloc(sizeof(char) * (
          17 + strlen(reinterpret_cast<char*>(client->client_pubkey)) + 
          strlen(reinterpret_cast<char*>(keypair_->public_key))
        ));
  int bc = sprintf(buffer, "%d%d%s%s", random1, client->random2, 
      keypair_->public_key, client->client_pubkey);

  if(bc == -1) ; // error
  
  // Master Secret.
  std::string ms = md5(buffer);
  char* body = (char*)malloc(sizeof(char)*(
        24 + ms.size()
        ));
  int mc = sprintf(body, "{\"type\":\"SFIN\",\"ms\":\"%s\"}", ms.c_str());
  if(mc == -1) ; // error

  conn->Write(body);
  free(buffer);
  free(body);
}

const char* CustomSSLServer::SSLRead(std::string& enc_msg){
  return enc_msg.c_str();
}


void CustomSSLServer::OnSSLReadCompletion(const AsyncConnectionPtr& conn, Buffer* buffer){
  InetAddress cl_addr = conn->local_addr();

  std::map<InetAddress, ClientInfo*>::iterator half_cli_iter = 
    half_connections_.find(cl_addr);

  if(connections_.find(cl_addr) != connections_.end()){
    std::string enc_msg = buffer->TakeAsString();
    const char* msg = SSLRead(enc_msg);
    OnReadCompletion(conn, msg);
  }
  else if(half_cli_iter != half_connections_.end()){
    if(ConfirmACK(buffer->TakeAsString().c_str(), 
          half_cli_iter->second)){
      // ok.
      // mutex_.Lock();
      // connections_.insert(*half_cli_iter);
      // half_connections_.erase(half_cli_iter);
      // mutex_.Unlock();

      assert(connections_.find(cl_addr) != connections_.end());
      
      LOG_TRACE("handshake over.");

      ServerFinish(conn, connections_.find(cl_addr)->second);
    }
    else {
      // log out error. confirm ack failed.
    }
  }
  else{
    // new SSL connection.
    if(IsClientHello(buffer->TakeAsString().c_str(), cl_addr)){
      // half_connections_.insert(std::make_pair(cl_addr, ))
      ServerHello(conn);
      
    } else {
      ; // log out error. not a SSL connection.
    }
  }
}

void CustomSSLServer::OnReadCompletion(const AsyncConnectionPtr& conn, const char* buffer){
  LOG_TRACE("peer=%s:%d, %s",conn->peer_addr().ip().c_str(),
      conn->peer_addr().port(), buffer);
}
