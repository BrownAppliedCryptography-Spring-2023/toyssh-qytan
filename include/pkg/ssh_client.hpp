#pragma once

#include <string>

#include "drivers/network_driver.hpp"
#include "drivers/crypto_driver.hpp"

extern "C" {
  #include "packet.h"
}

#define MAX_BUF (1 << 12) // It is not enough in reality

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