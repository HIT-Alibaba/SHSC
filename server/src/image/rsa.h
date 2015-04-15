#ifndef _SHSC_IMAGE_RSA_H_
#define _SHSC_IMAGE_RSA_H_

#include <stdio.h>
#include <stdlib.h>

#include <openssl/rsa.h>

namespace shsc {

struct KeyPair{
  unsigned char* public_key;
  unsigned char* private_key;
};

class ShscRSA {

  public:

    ShscRSA(int padding): padding_(padding){}

    KeyPair* GetKeyPair();

    int PublicEncrypt(const unsigned char* data, int sz, unsigned char* key,
        unsigned char* encrypted);

    int PrivateDecrypt(const unsigned char* enc_data, int sz, unsigned char* key, 
        unsigned char* decrypted);

    int PublicDecrypt(const unsigned char* enc_data, int sz, unsigned char* key, 
        unsigned char* decrypted);

    int PrivateEncrypt(const unsigned char* data, int sz, unsigned char* key, 
        unsigned char* encrypted);

    void PrintLastError(char* msg);
    
    RSA* CreateRSA(unsigned char* key, int pub);

  private:

    int padding_;
};

} // namespace shsc

#endif // _SHSC_IMAGE_RSA_H_
