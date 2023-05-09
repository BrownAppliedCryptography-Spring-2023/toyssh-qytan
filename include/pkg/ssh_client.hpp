#pragma once

#include <string>

#include "drivers/network_driver.hpp"
#include "drivers/crypto_driver.hpp"

class SSHClient {
public:
  SSHClient(std::string address, int port);
  ~SSHClient();
  void run();

private:
  std::string address;
  int port;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<SSHNetworkDriver> network_driver;

  void key_exchange();
};