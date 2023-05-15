#pragma once
#include <cryptopp/xed25519.h>
#include "drivers/crypto_driver.hpp"

class ED25519 : public DSADriver {
public:
  std::string get_name() override;
  std::pair<std::string, std::string> import_auth_key(const std::string &file) override;
  std::string DSA_sign(const std::string &pk, const std::vector<CryptoPP::byte> &input) override;
  bool DSA_verify(const std::string &vk, const std::string &message, const std::string signature) override;
  std::string get_sign_pubkey_blob_from_file(const std::vector<unsigned char> &data, size_t &idx) override;
  std::string get_sign_privkey_blob_from_file(const std::vector<unsigned char> &data, size_t &idx) override;

  std::string get_sign_pubkey(const std::vector<unsigned char> &data, size_t &idx) override;
  void put_sign_pubkey(std::vector<unsigned char> &data, const std::string &pub) override;
  std::string get_signature(const std::vector<unsigned char> &data, size_t &idx) override;
  void put_signature(std::vector<unsigned char> &data, const std::string &signature) override;
};