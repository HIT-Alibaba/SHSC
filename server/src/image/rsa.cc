#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

#include "image/rsa.h"

// openssl lib
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

using namespace shsc;

KeyPair* ShscRSA::GetKeyPair(){
  system("openssl genrsa -out private.pem 2048");
  system("openssl rsa -in private.pem -outform PEM -pubout -out public.pem");
  
  if (!KeyPairFileAlreadyExisted()) return NULL; 
  return ReadKeyPairFromFile();
}

bool ShscRSA::KeyPairFileAlreadyExisted() {
  if (access("private.pem", R_OK == -1)) return false;
  if (access("public.pem", R_OK == -1)) return false;
  return true;
}

KeyPair* ShscRSA::GetExistedKeyPair() {
  if (!KeyPairFileAlreadyExisted()) return NULL; 
  return ReadKeyPairFromFile();
}

KeyPair* ShscRSA::ReadKeyPairFromFile(){
  FILE *pri, *pub;
  KeyPair* pair = new KeyPair();

  pri = fopen("private.pem", "r");
  if(pri == NULL) return NULL;

  // determine the size of file.
  fseek(pri, 0L, SEEK_END);
  int sz = ftell(pri);

  pair->private_key = (unsigned char*) malloc (sz * sizeof(char));
  fseek(pri, 0L, SEEK_SET);

  int r = fread(pair->private_key, sizeof(char), sz, pri);
  fclose(pri);
  if(r != sz) return NULL;
  
  pub = fopen("public.pem", "r");
  if(pub == NULL) return NULL;
  fseek(pub, 0L, SEEK_END);
  sz = ftell(pub);
  pair->public_key = (unsigned char*) malloc (sz * sizeof(char));
  fseek(pub, 0L, SEEK_SET);

  r = fread(pair->public_key, sizeof(char), sz, pub);
  fclose(pub);
  if(r != sz) return NULL;

  return pair;
}

int32_t ShscRSA::GenerateRandomInt(){
   int32_t v;
   if (RAND_bytes((unsigned char *)&v, sizeof v ) == 0) {
      ERR_print_errors_fp(stderr);     
      return 0;
   }
   // Make sure it's an 8-digit number
   int32_t t = abs(v) % 100000000;
   if (t < 10000000) t += 10000000;
   return t;
}

RSA* ShscRSA::CreateRSA(unsigned char * key, int pub){
  RSA* rsa = NULL;
  BIO* keybio;
  keybio = BIO_new_mem_buf(key, -1);
  
  if(keybio == NULL) return NULL;
  if(pub){
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
  } else {
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
  }

  if (rsa == NULL) return NULL; // log out err;

  return rsa;
}

int ShscRSA::PublicDecrypt(const unsigned char* enc_data, int sz, unsigned char* key, 
    unsigned char* decrypted){
  RSA* rsa = CreateRSA(key, 1);
  int result = RSA_public_decrypt(sz, enc_data, decrypted, rsa, padding_);
  return result;
}

int ShscRSA::PublicEncrypt(const unsigned char* data, int sz, unsigned char* key, 
    unsigned char* encrypted){
  RSA* rsa = CreateRSA(key, 1);
  int result = RSA_public_encrypt(sz, data, encrypted, rsa, padding_);
  return result;
}

int ShscRSA::PrivateDecrypt(const unsigned char* enc_data, int sz, unsigned char* key, 
    unsigned char* decrypted){
  RSA* rsa = CreateRSA(key, 0);
  int result = RSA_private_decrypt(sz, enc_data, decrypted, rsa, padding_);
  return result;
}

int ShscRSA::PrivateEncrypt(const unsigned char* data, int sz, unsigned char* key,
    unsigned char* encrypted){
  RSA* rsa = CreateRSA(key, 0);
  int result = RSA_private_encrypt(sz, data, encrypted, rsa, padding_);
  return result;
}

void ShscRSA::PrintLastError(char* msg){
  char* err = (char*)malloc(130);
  ERR_load_crypto_strings();
  ERR_error_string(ERR_get_error(), err);
  printf("%s ERROR: %s\n", msg, err);
  free(err);
}
