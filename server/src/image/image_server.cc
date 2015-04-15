#include "image_server.h"
#include "md5.h"

#include <boost/bind.hpp>

using namespace shsc;

ImageServer::ImageServer(EventPool* event_pool, const InetAddress& bindaddr)
  : CustomSSLServer(event_pool, bindaddr)
{ }


bool ImageServer::AddImage(const InetAddress& address, const std::string& filename,
    const std::string &image,
    const std::string& checksum){
  if(!CheckHash(image, checksum)) return false;
  
  // lock?
  mutex_.Lock();
  files_.insert(make_pair(filename, address));
  mutex_.Unlock();
  return true;
}

bool ImageServer::QueryImage(const std::string& filename, InetAddress& address){
  std::map<std::string, InetAddress>::iterator iter = files_.find(filename);
  if(iter == files_.end()) return false;
  address = iter->second;
  return true;
}

std::vector<std::string> ImageServer::QueryFiles(){
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

