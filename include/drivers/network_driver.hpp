#pragma once
#include <cstring>
#include <iostream>

#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>

#include "util/messages.hpp"

class NetworkDriver {
public:
  virtual void listen(int port) = 0;
  virtual void connect(std::string address, int port) = 0;
  virtual void disconnect() = 0;
  virtual void send(std::vector<unsigned char>& data) = 0;
  virtual std::vector<unsigned char> read(size_t length) = 0;
  virtual std::string get_remote_info() = 0;
};

class SSHNetworkDriver : public NetworkDriver {
public:
  SSHNetworkDriver();
  void listen(int port) override;
  void connect(std::string address, int port) override;
  void disconnect() override;
  void send(std::vector<unsigned char>& data) override;
  std::vector<unsigned char> read(size_t length) override;
  std::string get_remote_info() override;

public:
  void ssh_send_banner();
  void ssh_recv_banner();

private:
  bool kex = false;
  boost::asio::io_context io_context;
  std::shared_ptr<boost::asio::ip::tcp::socket> socket;
};
