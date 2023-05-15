#pragma once

#include <chrono>
#include <cmath>
#include <cryptopp/secblockfwd.h>
#include <cstdlib>
#include <iostream>
#include <string>

#include <cryptopp/cryptlib.h>
#include <cryptopp/xed25519.h>
#include <cryptopp/dsa.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/hmac.h>
#include <cryptopp/integer.h>
#include <cryptopp/modes.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rijndael.h>
#include <cryptopp/sha.h>

#include "util/messages.hpp"

class DSADriver {
public:
  virtual std::string get_name() = 0;
  virtual std::pair<std::string, std::string> import_auth_key(const std::string &file) = 0;
  virtual std::string DSA_sign(const std::string &pk, const std::vector<CryptoPP::byte> &input) = 0;
  virtual bool DSA_verify(const std::string &vk, const std::string &message, const std::string signature) = 0;
  virtual std::string get_sign_pubkey_blob_from_file(const std::vector<unsigned char> &data, size_t &idx) = 0;
  virtual std::string get_sign_privkey_blob_from_file(const std::vector<unsigned char> &data, size_t &idx) = 0;

  virtual std::string get_sign_pubkey(const std::vector<unsigned char> &data, size_t &idx) = 0;
  virtual void put_sign_pubkey(std::vector<unsigned char> &data, const std::string &pub) = 0;
  virtual std::string get_signature(const std::vector<unsigned char> &data, size_t &idx) = 0;
  virtual void put_signature(std::vector<unsigned char> &data, const std::string &signature) = 0;
};

class CryptoDriver {
public:
  CryptoDriver() = default;
  CryptoDriver(std::shared_ptr<DSADriver> dsa) : dsa(dsa) {}

public:
  std::tuple<CryptoPP::x25519, CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> DH_initialize();
  CryptoPP::SecByteBlock
  DH_generate_shared_key(const CryptoPP::x25519 &DH_obj, const CryptoPP::SecByteBlock &DH_private_value,
                         const CryptoPP::SecByteBlock &DH_other_public_value);

  std::string DSA_sign(const std::string &pk, const std::vector<CryptoPP::byte> &input);
  bool DSA_verify(const std::string &vk, const std::string &message, const std::string signature);

  void Enc_setup(const CryptoPP::SecByteBlock &enc_key, const CryptoPP::SecByteBlock &enc_iv,
            const CryptoPP::SecByteBlock &dec_key, const CryptoPP::SecByteBlock &dec_iv);
  void Enc_encrypt(const std::vector<unsigned char> &plaintext, std::vector<unsigned char> &cipher);
  void Enc_decrypt(const std::vector<unsigned char> &ciphertext, std::vector<unsigned char> &recover);

  std::vector<CryptoPP::byte> HMAC_generate(CryptoPP::SecByteBlock key, const std::vector<CryptoPP::byte> &ciphertext);
  bool HMAC_verify(CryptoPP::SecByteBlock key, std::string ciphertext, std::string hmac);

  CryptoPP::SecByteBlock prg(const CryptoPP::SecByteBlock &seed, CryptoPP::SecByteBlock iv, int size);
  CryptoPP::Integer nowish();
  CryptoPP::SecByteBlock png(int numBytes);
  std::string hash(std::string msg);

public:
  void setup() {} // todo: setup according to the algorithm;
  std::string get_pki_name();
  std::pair<std::string, std::string> import_auth_key(const std::string &file);
  std::string get_session_id(
    std::string server_banner,
    std::string client_banner,
    std::vector<unsigned char> &client_kex_init,
    std::vector<unsigned char> &server_kex_init,
    std::string host_key,
    CryptoPP::SecByteBlock client_pub,
    CryptoPP::SecByteBlock server_pub,
    CryptoPP::SecByteBlock shared_key
  );
  int put_shared_secret(std::vector<unsigned char> &buf, 
                      const unsigned char *x, long long len);
  
  std::string get_sign_pubkey_blob_from_file(const std::vector<unsigned char> &data, size_t &idx);
  std::string get_sign_privkey_blob_from_file(const std::vector<unsigned char> &data, size_t &idx);

  std::string get_sign_pubkey(const std::vector<unsigned char> &data, size_t &idx);
  void put_sign_pubkey(std::vector<unsigned char> &data, const std::string &pub);
  std::string get_signature(const std::vector<unsigned char> &data, size_t &idx);
  void put_signature(std::vector<unsigned char> &data, const std::string &signature);

private:
  std::shared_ptr<DSADriver> dsa;
  CryptoPP::CTR_Mode< CryptoPP::AES >::Decryption d;
  CryptoPP::CTR_Mode< CryptoPP::AES >::Encryption e;
};
