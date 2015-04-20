#include "image_server.h"
#include "md5.h"

#include <boost/bind.hpp>
#include <rapidjson/document.h>

using namespace rapidjson;
using namespace shsc;

ImageServer::ImageServer(EventPool* event_pool, const InetAddress& bindaddr)
  : CustomSSLServer(event_pool, bindaddr)
{ }


void ImageServer::OnReadCompletion(const AsyncConnectionPtr & conn, const char* buffer){
  LOG_TRACE("image server recieved: %s, %d", buffer, strlen(buffer));
   
  Document document;
  document.Parse(buffer);

  if(!document.HasMember("type")) ; // error
  
  std::string type = document["type"].GetString();
  if(type == "ADD"){
    std::string filename = document["filename"].GetString();
    std::string checksum = document["checksum"].GetString();
    std::string image_checksum = document["image_checksum"].GetString();
    std::string ip = document["ip"].GetString();
    int port = document["port"].GetInt();


    // insert image node's listenning socket into map--> 
    // client write-read socket address <-> client listening socket address
    InetAddress addr = InetAddress(ip, port);
    client_listen_map_[conn->peer_addr()] = addr;

    if(AddImage(addr, filename, checksum, image_checksum)){
      LOG_TRACE("%s:%d add image : %s", conn->peer_addr().ip().c_str(), 
          conn->peer_addr().port(), filename.c_str() );
      SSLWrite(conn, "add image ok.");
    }
    else{
      SSLWrite(conn, "add image failed.");
    }
  } 
  else if (type=="QUERY"){
    std::string filename = document["filename"].GetString();
    InetAddress filenode;
    if(QueryImage(filename, filenode)){
      LOG_TRACE("filename / filenode: %s / %s : %d", filename.c_str(), filenode.ip().c_str(), 
          filenode.port());

      ClientInfo* client = connections_[conn->peer_addr()];
      // send client ms to filenode.
      // send filenode ms to client.
      
      //...

    } else {
      LOG_TRACE("query failed: %s", filename.c_str()); 
    }
  }
  else if(type=="ALL"){
    auto v = AllFiles();
    const char* r = vatoc(v);
    if(r != NULL){ 
      SSLWrite(conn, r);
      LOG_TRACE("%s:%d query all files", conn->peer_addr().ip().c_str(), 
          conn->peer_addr().port()); 
    }
    else{
      LOG_TRACE("%s:%d query all files failed.", conn->peer_addr().ip().c_str(), 
          conn->peer_addr().port());
      SSLWrite(conn, "query all files failed");
    }
  }
}

const char* ImageServer::vatoc(const std::vector<std::string> files){
  if (files.size() == 0) return NULL;
  std::string f;

  for(size_t i = 0; i < files.size(); i++){
    if(f.size()!=0) f+=",";
    f+="\""+files[i]+"\"";
  }

  std::string filearray = "["+f+"]";
  std::string checksum = md5(filearray.c_str());
  
  // {"files":[...], "checksum":md5 of files}
  char* r = (char*) malloc(filearray.size() + checksum.size() + 22);
  int rz = sprintf(r, "{\"files\":%s,\"checksum\":\"%s\"}", 
      filearray.c_str(), checksum.c_str());

  if(rz == -1) ; //error

  return r;
}

bool ImageServer::AddImage(const InetAddress& address, const std::string& filename,
    const std::string& checksum,
    const std::string& image_checksum){
  if(!CheckHash(filename, checksum)) return false;
  
  // lock?
  mutex_.Lock();
  files_.insert(make_pair(filename, make_pair(address, image_checksum)));
  mutex_.Unlock();
  return true;
}

bool ImageServer::QueryImage(const std::string& filename, InetAddress& address){
  std::map<std::string, std::pair<InetAddress, std::string> >::iterator iter = files_.find(filename);
  if(iter == files_.end()) return false;
  address = iter->second.first;
  return true;
}

std::vector<std::string> ImageServer::AllFiles(){
  std::vector<std::string> result;
  for(auto iter = files_.begin(); iter != files_.end(); iter++){
    result.push_back(iter->first);
  }
  return result;
}

bool ImageServer::CheckHash(std::string file, std::string checksum){
  std::string hash = md5(file);
  if(checksum != hash) return false;
  return true;
}

