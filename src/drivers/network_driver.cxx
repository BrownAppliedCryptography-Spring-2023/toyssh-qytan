#include <boost/asio/completion_condition.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/system/error_code.hpp>
#include <netinet/in.h>
#include <stdexcept>
#include <vector>

#include "util/constants.hpp"
#include "drivers/network_driver.hpp"
#include "util/logger.hpp"

using namespace boost::asio;
using ip::tcp;

namespace {
  src::severity_logger<logging::trivial::severity_level> lg;
}

/**
 * Constructor. Sets up IO context and socket.
 */
SSHNetworkDriver::SSHNetworkDriver() : io_context() {
  this->socket = std::make_shared<tcp::socket>(io_context);
}

/**
 * Listen on the given port at localhost.
 * @param port Port to listen on.
 */
void SSHNetworkDriver::listen(int port) {
  tcp::acceptor acceptor(this->io_context, tcp::endpoint(tcp::v4(), port));
  acceptor.accept(*this->socket);
}

/**
 * Connect to the given address and port.
 * @param address Address to connect to.
 * @param port Port to conect to.
 */
void SSHNetworkDriver::connect(std::string address, int port) {
  if (address == "localhost")
    address = "127.0.0.1";
  this->socket->connect(
      tcp::endpoint(boost::asio::ip::address::from_string(address), port));
}

/**
 * Disconnect graceefully.
 */
void SSHNetworkDriver::disconnect() {
  this->socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both);
  this->socket->close();
  this->io_context.stop();
}

/**
 * Sends a fixed amount of data by sending length first.
 * @param data Bytes of data to send.
 */
void SSHNetworkDriver::send(const std::vector<unsigned char>& data) {
  boost::asio::write(*this->socket, boost::asio::buffer(data));
}

/**
 * Receives a fixed amount of data by receiving length first.
 * @return std::vector<unsigned char> data read.
 * @throws error when eof.
 */
std::vector<unsigned char> SSHNetworkDriver::read() {
  // read message
  boost::system::error_code error;
  uint32_t len;
  boost::asio::read(*this->socket, boost::asio::buffer(&len, sizeof len),
                    boost::asio::transfer_exactly(sizeof len), error);
  if (error) {
    throw std::runtime_error("Received EOF.");
  }

  len = ntohl(len);
  std::vector<unsigned char> data(len);

  boost::asio::read(*this->socket, boost::asio::buffer(data),
                    boost::asio::transfer_exactly(len), error);
  if (error) {
    throw std::runtime_error("Received EOF.");
  }
  
  Packet packet;
  packet.deserialize_without_length(data);
  return packet.payload;
}

std::vector<unsigned char> SSHNetworkDriver::read(size_t size) {
  boost::system::error_code error;
  std::vector<unsigned char> data(size);

  auto n = boost::asio::read(*this->socket, boost::asio::buffer(data),
                    boost::asio::transfer_exactly(size), error);
  if (n != size) {
    CUSTOM_LOG(lg, error) << "expected size: " << size << " real size: " << n;
    throw std::runtime_error("read failed");
  }
  assert(n == size);
  if (error) {
    throw std::runtime_error("Received EOF.");
  }
  return data;
}

/**
 * Get socket info as string.
 */
std::string SSHNetworkDriver::get_remote_info() {
  return this->socket->remote_endpoint().address().to_string() + ":" +
         std::to_string(this->socket->remote_endpoint().port());
}


void SSHNetworkDriver::ssh_send_banner() {
  std::string data = banner;
  std::string terminate = "\r\n";
  data.insert(data.end(), terminate.begin(), terminate.end());
  /* The maximum banner length is 255 for SSH2 */
  std::vector<unsigned char> buffer(data.begin(), data.end());

  this->send(buffer);
}

std::string SSHNetworkDriver::ssh_recv_banner() {
  /* The maximum banner length is 255 for SSH2 */
  // boost::asio::streambuf buf(255);
  // When it is in the same packet, read_until has bug.
  // boost::asio::read_until(*this->socket, buf, "\r\n");
  // std::string data = boost::asio::buffer_cast<const char*>(buf.data());
  std::string peer_banner;
  char c1 = 0, c2 = 0;
  boost::system::error_code error;
  while(!(c1 == '\r' && c2 == '\n')) {
    c1 = c2;
    boost::asio::read(*this->socket, boost::asio::buffer(&c2, 1),
                        boost::asio::transfer_exactly(1), error);
    peer_banner += c2;
    if (error) {
      throw std::runtime_error("Received EOF.");
    }
  }
  
  boost::algorithm::trim(peer_banner);
  return peer_banner;
}
