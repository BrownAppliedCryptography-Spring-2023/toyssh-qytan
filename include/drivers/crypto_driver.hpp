#pragma once

#include <chrono>
#include <cmath>
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

using namespace CryptoPP;

namespace ALGO_TYPE {
enum T {
    KEX,
    HOST_KEY,
    ENCRYPT_CLIENT_TO_SERVER,
    ENCRYPT_SERVER_TO_CLIENT,
    MAC_CLIENT_TO_SERVER,
    MAC_SERVER_TO_CLIENT,
    COMPRESS_CLIENT_TO_SERVER,
    COMPRESS_SERVER_TO_CLIENT,
};
}

class CryptoDriver {
public:

  std::tuple<x25519, SecByteBlock, SecByteBlock> curve25519_initialize();
  SecByteBlock
  curve25519_generate_shared_key(const x25519 &DH_obj, const SecByteBlock &DH_private_value,
                         const SecByteBlock &DH_other_public_value);

  bool ed25519_verify(const std::string &vk, const std::string &message, const std::string signature);

  SecByteBlock AES_generate_key(const SecByteBlock &DH_shared_key);
  std::pair<std::string, SecByteBlock> AES_encrypt(SecByteBlock key,
                                                   std::string plaintext);
  std::string AES_decrypt(SecByteBlock key, SecByteBlock iv,
                          std::string ciphertext);

  SecByteBlock HMAC_generate_key(const SecByteBlock &DH_shared_key);
  std::string HMAC_generate(SecByteBlock key, std::string ciphertext);
  bool HMAC_verify(SecByteBlock key, std::string ciphertext, std::string hmac);


  SecByteBlock prg(const SecByteBlock &seed, SecByteBlock iv, int size);
  Integer nowish();
  SecByteBlock png(int numBytes);
  std::string hash(std::string msg);
  void algo_select(std::string& choices, ALGO_TYPE::T);
};
