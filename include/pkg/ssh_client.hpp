#pragma once

#include <cryptopp/secblockfwd.h>
#include <cstdint>
#include <memory>
#include <string>

#include "pkg/ssh_channel.hpp"
#include "drivers/network_driver.hpp"
#include "drivers/crypto_driver.hpp"

#define MAX_BUF (1 << 12) // It is not enough in reality

class SSHClient {
public:
  explicit SSHClient(
    std::string name, std::string pk_file, std::string address, int port);
  ~SSHClient();
  void run();

private:  
  uint32_t send_packet_id;
  uint32_t recv_packet_id;
  std::string name;
  std::string pk_file;
  std::string address;
  int port;
  bool kex = false;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<SSHNetworkDriver> network_driver;

  std::vector<Channel> channels;
  std::string server_banner;
  std::string session_id;
  CryptoPP::SecByteBlock shared_key;

  CryptoPP::SecByteBlock iv_client_to_server;
  CryptoPP::SecByteBlock enc_client_to_server;
  CryptoPP::SecByteBlock mac_client_to_server;
  CryptoPP::SecByteBlock iv_server_to_client;
  CryptoPP::SecByteBlock enc_server_to_client;
  CryptoPP::SecByteBlock mac_server_to_client;

  std::vector<unsigned char> read();
  void send(const std::vector<unsigned char> &data);
  void key_derive();
  void key_exchange();
  void auth();
  uint32_t open_channel();
  void close_channel(uint32_t id);
  void handle_channel_request(uint32_t id, std::vector<CryptoPP::byte> &data);
  
  void ReceiveThread();
  void SendThread(uint32_t id);
  friend class Channel;
};