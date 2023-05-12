#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#include <boost/chrono.hpp>
#include <boost/thread.hpp>
#include <cryptopp/cryptlib.h>
#include <cryptopp/dsa.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>

// ================================================
// MESSAGE TYPES
// ================================================

namespace MessageType {
enum T {
  UserToServer_SSH_KEX_Message = 2,
  ServerToUser_SSH_KEX_Message = 3,
};
};
// MessageType::T get_message_type(std::vector<unsigned char> &data);

// ================================================
// SERIALIZABLE
// ================================================

struct Serializable {
  using buf = std::vector<unsigned char>;
  using const_buf = const buf;
  virtual buf serialize() = 0;
  virtual int deserialize(const_buf &data) = 0;
};

// ================================================
// WRAPPERS
// ================================================

struct HMACTagged_Wrapper : public Serializable {
  std::vector<unsigned char> payload;
  CryptoPP::SecByteBlock iv;
  std::string mac;

  buf serialize() override;
  int deserialize(const_buf &data) override;
};

struct Packet : Serializable {
  uint32_t    packet_length;
  uint8_t     padding_length;
  buf         payload;
  buf         padding;
  buf         mac;

  buf serialize() override;
  int deserialize(const_buf &data, bool mac);

private:
  int deserialize(const_buf &data) override;
};

// ================================================
// MESSAGES
// ================================================

// struct HMACTagged_Wrapper : public Serializable {
//   std::vector<unsigned char> payload;
// //   CryptoPP::SecByteBlock iv;
//   std::string mac;

//   void serialize(std::vector<unsigned char> &data);
//   int deserialize(std::vector<unsigned char> &data);
// };

// struct Certificate_Message : public Serializable {
//   std::string id;
// //   CryptoPP::DSA::PublicKey verification_key;
//   std::string server_signature; // computed on id + verification_key

//   void serialize(std::vector<unsigned char> &data);
//   int deserialize(std::vector<unsigned char> &data);
// };

// ================================================
// USER <=> SERVER MESSAGES
// ================================================
