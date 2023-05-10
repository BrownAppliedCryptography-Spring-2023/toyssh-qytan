#include <boost/asio.hpp>
#include <memory>
#include <sodium/randombytes.h>
#include <stdexcept>
#include <sys/wait.h>

#include "pkg/ssh_client.hpp"
#include "util/messages.hpp"
#include "util/ssh.hpp"
#include "util/util.hpp"
#include "util/logger.hpp"
#include "crypto/algorithms.hpp"

extern "C" {
#include "packet.h"
#include "randombytes.h"
}

namespace {
    src::severity_logger<logging::trivial::severity_level> lg;
}

SSHClient::SSHClient(std::string address, int port)
    : address(address), port(port)
{
    this->network_driver = ::std::make_shared<SSHNetworkDriver>();
    this->network_driver->connect(address, port);

    this->network_driver->ssh_send_banner();
    this->network_driver->ssh_recv_banner();
}

namespace {

std::vector<unsigned char> kex_algo_send() {
    std::vector<unsigned char> data;
    data.push_back(SSH_MSG_KEXINIT);    /* SSH_MSG_KEXINIT */

    unsigned char cookie[16];
    randombytes(cookie, 16);
    data.insert(data.end(), std::begin(cookie), std::end(cookie));

    ssh_algo_put(data, kexs);
    ssh_algo_put(data, host_keys);
    ssh_algo_put(data, ciphers);
    ssh_algo_put(data, ciphers);

    put_string(data, MAC_ALGO);
    put_string(data, MAC_ALGO);

    put_string(data, "none");
    put_string(data, "none");

    put_string(data, "");
    put_string(data, "");

    put_integer_big(0_u8, data);
    put_integer_big(0_u32, data);

    Packet packet;
    packet.payload = std::move(data);
    return packet.serialize();
}

void kex_algo_recv(const std::vector<unsigned char> &data) {
    size_t idx = 0;
    unsigned char c;
    
    get_integer_big(&c, data, idx);
    if (c != SSH_MSG_KEXINIT) {
        throw std::runtime_error("error state in kex_init: " + std::string(1, c));
    }

    idx += 16;          // skip cookie
    
    auto kex = get_string(data, idx);
    CUSTOM_LOG(lg, debug) << kex;
    algo_select(kex, ALGO_TYPE::KEX);
    
    auto key = get_string(data, idx);
    CUSTOM_LOG(lg, debug) << key;
    algo_select(key, ALGO_TYPE::HOST_KEY);

    auto ccipher = get_string(data, idx);   /* encryption algorithms client to server */
    CUSTOM_LOG(lg, debug) << ccipher;
    algo_select(ccipher, ALGO_TYPE::ENCRYPT_CLIENT_TO_SERVER);

    auto scipher = get_string(data, idx);   /* encryption algorithms server to client */
    CUSTOM_LOG(lg, debug) << scipher;
    algo_select(scipher, ALGO_TYPE::ENCRYPT_SERVER_TO_CLIENT);

    auto cmac = get_string(data, idx);      /* mac algorithms client to server */
    CUSTOM_LOG(lg, debug) << cmac;
    algo_select(cmac, ALGO_TYPE::MAC_CLIENT_TO_SERVER);

    auto smac = get_string(data, idx);      /* mac algorithms server to client */
    CUSTOM_LOG(lg, debug) << smac;
    algo_select(smac, ALGO_TYPE::MAC_SERVER_TO_CLIENT);

    get_string(data, idx);      /* compress algorithms client to server */
    get_string(data, idx);      /* compress algorithms server to client */
    get_string(data, idx);      /* languages client to server */
    get_string(data, idx);      /* languages client to server */

    uint8_t packet_follows;
    get_integer_big(&packet_follows, data, idx);

    uint32_t reserved;
    get_integer_big(&reserved, data, idx);

    assert(idx == data.size());
}   

std::vector<unsigned char> kex_dh_send() {
    unsigned char sk[sshcrypto_dh_SECRETKEYMAX];
    unsigned char pk[sshcrypto_dh_PUBLICKEYMAX];

    auto &kex_algo = kexs[kex_idx];

    if (kex_algo.dh_keypair(pk, sk) != 0){
        throw std::runtime_error("generate ");
    }
}
}

void SSHClient::key_exchange() {
    auto data = kex_algo_send();
    network_driver->send(data);

    data = network_driver->read();
    kex_algo_recv(data);


}

void SSHClient::run() {
rekeying:
    this->key_exchange();
}

SSHClient::~SSHClient() {
    this->network_driver->disconnect();
}