#include <boost/asio.hpp>
#include <cryptopp/secblockfwd.h>
#include <cryptopp/xed25519.h>
#include <memory>
#include <stdexcept>
#include <sys/wait.h>

#include "drivers/crypto_driver.hpp"
#include "pkg/ssh_client.hpp"
#include "secblock.h"
#include "util/messages.hpp"
#include "util/ssh.hpp"
#include "util/util.hpp"
#include "util/logger.hpp"
#include "util/constants.hpp"


namespace {
    src::severity_logger<logging::trivial::severity_level> lg;
}

SSHClient::SSHClient(std::string address, int port)
    : address(address), port(port)
{
    this->crypto_driver = ::std::make_shared<CryptoDriver>();
    this->network_driver = ::std::make_shared<SSHNetworkDriver>();
    this->network_driver->connect(address, port);

    this->network_driver->ssh_send_banner();
    this->server_banner = this->network_driver->ssh_recv_banner();

}

namespace {

std::vector<unsigned char> kex_algo_send() {
    std::vector<unsigned char> data;
    data.push_back(SSH_MSG_KEXINIT);    /* SSH_MSG_KEXINIT */

    unsigned char cookie[16];
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

    return data;
}

void kex_algo_recv(const std::vector<unsigned char> &data,
    std::shared_ptr<CryptoDriver> crypto_driver) {
    size_t idx = 0;
    unsigned char c;
    
    get_integer_big(&c, data, idx);
    if (c != SSH_MSG_KEXINIT) {
        throw std::runtime_error("error state in kex_init: " + std::string(1, c));
    }

    idx += 16;          // skip cookie
    
    auto kex = get_string(data, idx);
    CUSTOM_LOG(lg, debug) << kex;
    crypto_driver->algo_select(kex, ALGO_TYPE::KEX);
    
    auto key = get_string(data, idx);
    CUSTOM_LOG(lg, debug) << key;
    crypto_driver->algo_select(key, ALGO_TYPE::HOST_KEY);

    auto ccipher = get_string(data, idx);   /* encryption algorithms client to server */
    CUSTOM_LOG(lg, debug) << ccipher;
    crypto_driver->algo_select(ccipher, ALGO_TYPE::ENCRYPT_CLIENT_TO_SERVER);

    auto scipher = get_string(data, idx);   /* encryption algorithms server to client */
    CUSTOM_LOG(lg, debug) << scipher;
    crypto_driver->algo_select(scipher, ALGO_TYPE::ENCRYPT_SERVER_TO_CLIENT);

    auto cmac = get_string(data, idx);      /* mac algorithms client to server */
    CUSTOM_LOG(lg, debug) << cmac;
    crypto_driver->algo_select(cmac, ALGO_TYPE::MAC_CLIENT_TO_SERVER);

    auto smac = get_string(data, idx);      /* mac algorithms server to client */
    CUSTOM_LOG(lg, debug) << smac;
    crypto_driver->algo_select(smac, ALGO_TYPE::MAC_SERVER_TO_CLIENT);

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

void put_sign_pubkey(std::vector<unsigned char> &data, 
                const std::string &pub) {
    std:: string algo_name = "ssh-ed25519";
    uint32_t len = algo_name.size() + 32 + 8;
    put_integer_big(len, data);
    put_string(data, algo_name);
    put_string(data, pub);
}

std::string get_sign_pubkey(
                const std::vector<unsigned char> &data, size_t &idx) {
    uint32_t len;
    get_integer_big(&len, data, idx);
    auto algo_name = get_string(data, idx);
    assert(algo_name == "ssh-ed25519");
    return get_string(data, idx);
}

std::string get_signature(
                const std::vector<unsigned char> &data, size_t &idx) {
    uint32_t len;
    get_integer_big(&len, data, idx);
    auto algo_name = get_string(data, idx);
    assert(algo_name == "ssh-ed25519");
    return get_string(data, idx);
}

void put_signature(std::vector<unsigned char> &data, 
                const std::string &signature) {
    std:: string algo_name = "ssh-ed25519";
    uint32_t len = algo_name.size() + 64 + 8;
    put_integer_big(len, data);
    put_string(data, algo_name);
    put_string(data, signature);
}


std::string get_session_id(
    std::string server_banner,
    std::string client_banner,
    std::vector<unsigned char> &client_kex_init,
    std::vector<unsigned char> &server_kex_init,
    std::string host_key,
    CryptoPP::SecByteBlock client_pub,
    CryptoPP::SecByteBlock server_pub,
    CryptoPP::SecByteBlock shared_key
) {
    std::vector<unsigned char> data;
    
    put_string(data, client_banner);
    put_string(data, server_banner);
    put_chvec(data, client_kex_init);
    put_chvec(data, server_kex_init);
    
    put_sign_pubkey(data, host_key);

    put_string(data, byteblock_to_string(client_pub));
    put_string(data, byteblock_to_string(server_pub));
    // put_string(data, byteblock_to_string(shared_key));
    buf_putsharedsecret_(data, shared_key.data(), shared_key.size());

    return std::string(data.begin(), data.end());
}

template<typename T>
void hexdump(std::string desr, const T& s) {
    std::cout << desr << ": ";
    for (auto c : s) {
        printf("%02X", (unsigned char) c);
    }
    std::cout << std::endl;
}

}

void SSHClient::key_derive() {
    auto hash = session_id;
    for (size_t i = 0; i < 6; i++) {
        std::vector<unsigned char> buf;
        buf_putsharedsecret_(buf, shared_key.data(), shared_key.size());
        buf.insert(buf.end(), hash.begin(), hash.end());
        put_integer_big(static_cast<uint8_t>('A' + i), buf);
        buf.insert(buf.end(), session_id.begin(), session_id.end());

        auto key = crypto_driver->hash(std::string(buf.begin(), buf.end()));

        // TODO: generalize extend for different size key
        // buf.clear();
        // buf_putsharedsecret_(buf, shared_key.data(), shared_key.size());
        // buf.insert(buf.end(), hash.begin(), hash.end());
        // buf.insert(buf.end(), key.begin(), key.end());
        // key += crypto_driver->hash(std::string(buf.begin(), buf.end()));

        if (i == 0) iv_client_to_server = std::move(string_to_byteblock(key));
        if (i == 1) iv_server_to_client = std::move(string_to_byteblock(key));
        if (i == 2) enc_client_to_server = std::move(string_to_byteblock(key));
        if (i == 3) enc_server_to_client = std::move(string_to_byteblock(key));
        if (i == 4) mac_client_to_server = std::move(string_to_byteblock(key));
        if (i == 5) mac_server_to_client = std::move(string_to_byteblock(key));
    }
}

void SSHClient::key_exchange() {
    auto data = kex_algo_send();
    Packet packet;
    packet.payload = data;
    network_driver->send(packet.serialize());
    auto client_kex_init = std::move(data); // store for hashing

    data = network_driver->read();
    kex_algo_recv(data, this->crypto_driver);
    auto server_kex_init = std::move(data);


    auto [dh, priv, pub] = crypto_driver->curve25519_initialize();
    
    // send client public key
    data.clear();
    data.push_back(SSH_MSG_KEXDH_INIT);
    put_integer_big(static_cast<uint32_t>(dh.PublicKeyLength()), data);
    data.insert(data.end(), pub.begin(), pub.end());
    
    packet.payload = std::move(data);
    network_driver->send(packet.serialize());

    // recv server public key
    data = network_driver->read();
    size_t idx = 0;
    unsigned char c;
    get_integer_big(&c, data, idx);
    if (c != SSH_MSG_KEXDH_REPLY) {
        throw std::runtime_error("error state in kex_init: " + std::string(1, c));
    }

    sign_pk = get_sign_pubkey(data, idx);
    auto server_pub = get_string(data, idx);
    hexdump("server pub", server_pub);
    auto signature = get_signature(data, idx);
    hexdump("signature", signature);
    shared_key = 
            crypto_driver->curve25519_generate_shared_key(dh, priv, 
                string_to_byteblock(server_pub));
    
    hexdump("shared_key", byteblock_to_string(shared_key));
    
    session_id = get_session_id(server_banner, banner, 
                                    client_kex_init, server_kex_init, sign_pk, pub, 
                                    string_to_byteblock(server_pub), shared_key);
    session_id = crypto_driver->hash(session_id);
    hexdump("session id", session_id); 

    // kex_derivation(shared_key, session_id, 'A', session_id, crypto_driver);
    key_derive();
    data = network_driver->read();
    if (data[0] != SSH_MSG_NEWKEYS) {
        throw std::runtime_error("need rekey");
    }

    hexdump("Client to Server IV", iv_client_to_server);
    hexdump("Server to Client IV", iv_server_to_client);
    hexdump("Client to Server Encryption Key", enc_client_to_server);
    hexdump("Server to Client Encryption Key", enc_server_to_client);
    hexdump("Client to Server Integrity Key", mac_client_to_server);
    hexdump("Server to Client Integrity Key", mac_server_to_client);

    // God knows why it will fail even if the output is the same as libssh
    // What's more, it seems that libssh doesn't verify this signature also.
    // 0000004086C2F55BF130863A6B9D8C186F03B1C80793B27C475D852A8F104BD0EB199E0552A74BD0B4C9D6F99944A3402398375A2B3C70604BB7E7918C91E05E
    // 86C2F55BF130863A6B9D8C186F03B1C80793B27C475D852A8F104BD0EB199E05
    ed25519::Verifier verifier(string_to_byteblock(sign_pk));
    auto valid = verifier.VerifyMessage((const unsigned char *)session_id.data(), session_id.size(), (const unsigned char *)signature.data(), signature.size());
    if (!valid) {
        throw std::runtime_error("failed to verify packet");
    }
    packet.payload = std::vector<unsigned char>(1, SSH_MSG_NEWKEYS);
    network_driver->send(packet.serialize());
    network_driver->kex = true;
}

void SSHClient::run() {
    this->key_exchange();
}

SSHClient::~SSHClient() {
    this->network_driver->disconnect();
}