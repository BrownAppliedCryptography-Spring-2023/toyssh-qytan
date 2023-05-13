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
  std::tuple<CryptoPP::x25519, CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> curve25519_initialize();
  CryptoPP::SecByteBlock
  curve25519_generate_shared_key(const CryptoPP::x25519 &DH_obj, const CryptoPP::SecByteBlock &DH_private_value,
                         const CryptoPP::SecByteBlock &DH_other_public_value);

  bool ed25519_verify(const std::string &vk, const std::string &message, const std::string signature);

  CryptoPP::SecByteBlock AES_generate_key(const CryptoPP::SecByteBlock &DH_shared_key);
  void AES_encrypt(const std::vector<unsigned char> &plaintext, std::vector<unsigned char> &cipher);
  void AES_decrypt(const std::vector<unsigned char> &ciphertext, std::vector<unsigned char> &recover);

  CryptoPP::SecByteBlock HMAC_generate_key(const CryptoPP::SecByteBlock &DH_shared_key);
  std::vector<CryptoPP::byte> HMAC_generate(CryptoPP::SecByteBlock key, const std::vector<CryptoPP::byte> &ciphertext);
  bool HMAC_verify(CryptoPP::SecByteBlock key, std::string ciphertext, std::string hmac);


  void Enc_Setup(const CryptoPP::SecByteBlock &enc_key, const CryptoPP::SecByteBlock &enc_iv,
            const CryptoPP::SecByteBlock &dec_key, const CryptoPP::SecByteBlock &dec_iv);
  CryptoPP::SecByteBlock prg(const CryptoPP::SecByteBlock &seed, CryptoPP::SecByteBlock iv, int size);
  CryptoPP::Integer nowish();
  CryptoPP::SecByteBlock png(int numBytes);
  std::string hash(std::string msg);
  void algo_select(std::string& choices, ALGO_TYPE::T);

private:
  std::string kex_name;
  std::string pki_name;
  std::string enc_name;
  CryptoPP::CTR_Mode< CryptoPP::AES >::Decryption d;
  CryptoPP::CTR_Mode< CryptoPP::AES >::Encryption e;
};
