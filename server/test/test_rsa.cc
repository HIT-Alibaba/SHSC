#include "rsa.h"

#include <iostream>
#include <string.h>

using namespace shsc;

int main(){
  ShscRSA * rsa = new ShscRSA(RSA_PKCS1_PADDING);
  KeyPair* pair = rsa->GetKeyPair();
  if(pair == NULL) std::cout << "error" << std::endl;
  std::cout << pair->public_key << std::endl;
  std::cout << pair->private_key << std::endl;
  
  char plain_text[2048/8] = "Hello RSA";

  unsigned char encrypted[4097] = {};
  unsigned char decrypted[4097] = {};

  int el = rsa->PublicEncrypt(reinterpret_cast<unsigned char*>(plain_text), strlen(plain_text), pair->public_key, encrypted);
  if(el == -1){
    rsa->PrintLastError("Public Encrypt failed "); 
  }
  std::cout << "el: " << el << std::endl;
  std::cout << encrypted << std::endl;

  int dl = rsa->PrivateDecrypt(reinterpret_cast<unsigned char*>(encrypted), el, pair->private_key, decrypted);
  if(dl == -1){
    rsa->PrintLastError("Private Decrypt failed.");
  }

  std::cout << decrypted << std::endl;

  return 0;
}


