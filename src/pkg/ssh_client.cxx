#include <boost/asio.hpp>
#include <memory>
// #include <sodium.h>

// #include "packet.h"
// #include "../../include/"
#include "pkg/ssh_client.hpp"
#include "util/ssh.hpp"
#include "util/util.hpp"
#include "crypto/algorithms.hpp"

SSHClient::SSHClient(std::string address, int port)
    : address(address), port(port)
{
    this->network_driver = ::std::make_shared<SSHNetworkDriver>();
    this->network_driver->connect(address, port);

    this->network_driver->ssh_send_banner();
    this->network_driver->ssh_recv_banner();
}

void SSHClient::key_exchange() {
    std::vector<unsigned char> data;
    data.push_back(SSH_MSG_KEXINIT); /* SSH_MSG_KEXINIT */

    unsigned char cookie[16];
    // randombytes_buf(cookie, 16);
    data.insert(data.end(), std::begin(cookie), std::end(cookie));

    // ssh_algo_put(data, kexs);
    // ssh_algo_put(data, host_keys);
    // ssh_algo_put(data, ciphers);
    // ssh_algo_put(data, ciphers);
    
}

void SSHClient::run() {
    
}

SSHClient::~SSHClient() {
    this->network_driver->disconnect();
}