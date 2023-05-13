#pragma once

#include <cryptopp/secblockfwd.h>
#include <string>

#include "drivers/network_driver.hpp"
#include "drivers/crypto_driver.hpp"

#define MAX_BUF (1 << 12) // It is not enough in reality

class SSHClient {
public:
  SSHClient(std::string name, std::string address, int port);
  ~SSHClient();
  void run();

private:
  uint32_t send_packet_id;
  uint32_t recv_packet_id;
  std::string address;
  std::string name;
  int port;
  bool kex = false;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<SSHNetworkDriver> network_driver;

  std::string server_banner;
  std::string session_id;
  std::string sign_pk;
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
};