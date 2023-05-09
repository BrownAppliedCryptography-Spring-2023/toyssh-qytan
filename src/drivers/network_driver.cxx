#include <stdexcept>
#include <vector>

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
void SSHNetworkDriver::send(std::vector<unsigned char>& data) {
  boost::asio::write(*this->socket, boost::asio::buffer(data));
}

/**
 * Receives a fixed amount of data by receiving length first.
 * @return std::vector<unsigned char> data read.
 * @throws error when eof.
 */
std::vector<unsigned char> SSHNetworkDriver::read(size_t length) {
  // read length
  boost::system::error_code error;

  // read message
  std::vector<unsigned char> data(length);
  boost::asio::read(*this->socket, boost::asio::buffer(data),
                    boost::asio::transfer_exactly(length), error);
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
  std::string banner = "SSH-2.0-toy_ssh\r\n";
  
  /* The maximum banner length is 255 for SSH2 */
  std::vector<unsigned char> buffer(banner.begin(), banner.end());

  this->send(buffer);
}

void SSHNetworkDriver::ssh_recv_banner() {
  /* The maximum banner length is 255 for SSH2 */
  boost::asio::streambuf buf(255);
  boost::asio::read_until(*this->socket, buf, "\r\n");
  std::string data = boost::asio::buffer_cast<const char*>(buf.data());

  CUSTOM_LOG(lg, debug) << data;
}
