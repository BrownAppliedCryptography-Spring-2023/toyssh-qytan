#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>
#include <cryptopp/filters.h>
#include <cryptopp/misc.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblockfwd.h>
#include <cryptopp/base64.h>
#include <cryptopp/xed25519.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <boost/thread.hpp>
#include <termios.h>
#include <signal.h>

#include "drivers/crypto_driver.hpp"
#include "drivers/ed25519_driver.hpp"
#include "drivers/rsa_driver.hpp"
#include "pkg/ssh_channel.hpp"
#include "pkg/ssh_client.hpp"
#include "secblock.h"
#include "util/messages.hpp"
#include "util/ssh.hpp"
#include "util/util.hpp"
#include "util/logger.hpp"
#include "util/constants.hpp"

namespace {

struct termios terminal;
src::severity_logger<logging::trivial::severity_level> lg(logging::trivial::warning);

void do_cleanup(int i) {
    /* unused variable */
    (void) i;

    tcsetattr(0, TCSANOW, &terminal);
}

void setup_shell() {
    struct termios terminal_local;
    tcgetattr(0, &terminal_local);
    memcpy(&terminal, &terminal_local, sizeof(struct termios));

    cfmakeraw(&terminal_local);
    tcsetattr(0, TCSANOW, &terminal_local);
    signal(SIGTERM, do_cleanup);
}

std::vector<CryptoPP::byte> kex_algo_send() {
    std::vector<CryptoPP::byte> data;
    data.push_back(SSH_MSG_KEXINIT);    /* SSH_MSG_KEXINIT */

    CryptoPP::byte cookie[16];
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

void kex_algo_recv(const std::vector<CryptoPP::byte> &data,
        std::shared_ptr<CryptoDriver> crypto) {
    size_t idx = 0;
    CryptoPP::byte c;
    
    get_integer_big(&c, data, idx);
    if (c != SSH_MSG_KEXINIT) {
        throw std::runtime_error("error state in kex_init: " + std::string(1, c));
    }

    idx += 16;          // skip cookie
    
    auto kex = get_string(data, idx);
    
    auto key = get_string(data, idx);

    auto ccipher = get_string(data, idx);   /* encryption algorithms client to server */

    auto scipher = get_string(data, idx);   /* encryption algorithms server to client */

    auto cmac = get_string(data, idx);      /* mac algorithms client to server */

    auto smac = get_string(data, idx);      /* mac algorithms server to client */

    // get_string(data, idx);      /* compress algorithms client to server */
    // get_string(data, idx);      /* compress algorithms server to client */
    // get_string(data, idx);      /* languages client to server */
    // get_string(data, idx);      /* languages client to server */

    // uint8_t packet_follows;
    // get_integer_big(&packet_follows, data, idx);

    // uint32_t reserved;
    // get_integer_big(&reserved, data, idx);

    // Todo: according to the algorithm to create crypto driver
    return crypto->setup();
}

template<typename T>
void hexdump(std::string desr, const T& s) {
    std::cout << desr << ":";
    size_t i = 0;
    for (auto c : s) {
        if (i % 8 == 0) printf(" ");
        if (i % 16 == 0) printf("\n");
        printf("%02X", (CryptoPP::byte) c);
        i++;
    }
    std::cout << std::endl;
}

std::vector<CryptoPP::byte> channel_request_head(
        uint32_t id, const std::string &req, CryptoPP::byte reply
) {
    std::vector<CryptoPP::byte> data;
    data.push_back(SSH_MSG_CHANNEL_REQUEST);
    put_integer_big(id, data);
    put_string(data, req);
    data.push_back(reply);
    return data;
}

std::vector<CryptoPP::byte> channel_request_pty(uint32_t id) {
    auto data = channel_request_head(id, "pty-req", 1);
    std::string terminal = "xterm";
    uint32_t col = 80, row = 24, pix = 0;
    put_string(data, terminal);
    put_integer_big(col, data);
    put_integer_big(row, data);
    put_integer_big(pix, data);
    put_integer_big(pix, data);
    put_string(data, "\0");         /* add a 0byte string */
    return data;
}

}

SSHClient::SSHClient(
    std::string name, std::string pk_file, std::string address, int port)
    : name(name), pk_file(pk_file), address(address), port(port)
{
    this->crypto_driver = ::std::make_shared<CryptoDriver>();
    this->network_driver = ::std::make_shared<SSHNetworkDriver>();
    this->network_driver->connect(address, port);

    this->network_driver->ssh_send_banner();
    this->server_banner = this->network_driver->ssh_recv_banner();
    this->send_packet_id = this->recv_packet_id = 0;
    if (pk_file.find("ed25519") != std::string::npos) {
        this->crypto_driver = std::make_shared<CryptoDriver>(
            std::make_shared<ED25519>()
        );
    } 
    /* todo: implement rsa sign scheme
    else if (pk_file.find("rsa") != std::string::npos) {
        crypto_driver->dsa = std::make_shared<RSADriver>();
    } 
    */
    else {
        throw std::runtime_error("unimplement pki algorithm");
    }
}

uint32_t SSHClient::open_channel() {
    // TODO: need mutex lock
    uint32_t id = channels.size();
    auto barrier = std::make_shared<boost::barrier>(1);
    channels.push_back(Channel(barrier));

    std::vector<CryptoPP::byte> data;
    data.push_back(SSH_MSG_CHANNEL_OPEN);
    put_string(data, "session");
    put_integer_big(id, data);
    put_integer_big(static_cast<uint32_t>(CHANNEL_INITIAL_WINDOW), data);
    put_integer_big(static_cast<uint32_t>(CHANNEL_MAX_PACKET), data);
    this->send(data);

    barrier->wait();
    return id;
}

void SSHClient::close_channel(uint32_t id) {
    std::vector<CryptoPP::byte> data;
    data.push_back(SSH_MSG_CHANNEL_CLOSE);
    put_integer_big(channels[id].receipt_id, data);
    this->send(data);
}

void SSHClient::handle_channel_request(uint32_t id, std::vector<CryptoPP::byte> &data) {
    size_t idx = 1 + sizeof(id);
    auto req = get_string(data, idx);
    bool reply = data[idx++];
    if (req == "exit-status") {
        uint32_t exit;
        get_integer_big(&exit, data, idx);
        channels[id].exit = exit;
    }
    if (reply) {
        throw std::runtime_error("unimplement channel request: " + req);
    }
}

void SSHClient::ReceiveThread() {
    std::vector<CryptoPP::byte> data;
    std::string req;
    CryptoPP::byte c;
    uint32_t id;
    size_t idx;

    for(;;) {
        data = this->read();
        c = data[0];
        idx = 1;
        get_integer_big(&id, data, idx);
        switch (c) {
        case SSH_MSG_GLOBAL_REQUEST:
            // in this case, id is the length of string
            req = std::string(data.begin() + idx, data.begin() + idx + id);
            idx += id;
            CUSTOM_LOG(lg, debug) << "global request: " << req;

            if (data[idx++]) {
                throw std::runtime_error("did not implement global request");
            }
            break;
        case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
            uint32_t recipient_id, init_windows, max_packet;
            get_integer_big(&recipient_id, data, idx);
            get_integer_big(&init_windows, data, idx);
            get_integer_big(&max_packet, data, idx);
            if (recipient_id < this->channels.size()) {
                this->channels[recipient_id].setup(
                    id, init_windows, max_packet
                );
            }
            break;
        case SSH_MSG_CHANNEL_REQUEST:
            this->handle_channel_request(id, data);
            break;
        case SSH_MSG_CHANNEL_DATA:
            std::cout << get_string(data, idx);
            std::cout.flush();
            break;
        case SSH_MSG_CHANNEL_EXTENDED_DATA:
            break;
        case SSH_MSG_DEBUG:
        case SSH_MSG_CHANNEL_SUCCESS:
        case SSH_MSG_CHANNEL_WINDOW_ADJUST:
            break;
        case SSH_MSG_CHANNEL_FAILURE:
            CUSTOM_LOG(lg, error) << "channel " << id << " failed";
            channels.erase(channels.begin() + id);
            break;
        case SSH_MSG_CHANNEL_EOF:
            break;
        case SSH_MSG_CHANNEL_CLOSE:
            this->close_channel(id);
            channels.erase(channels.begin() + id);
        case SSH_MSG_DISCONNECT:
            return;
        case SSH_MSG_KEXINIT:
            // rekey
            break;
        default:
            throw std::runtime_error("unimplement ssh message");
        }
    }
}

void SSHClient::key_derive() {
    auto hash = session_id;
    for (size_t i = 0; i < 6; i++) {
        std::vector<CryptoPP::byte> buf;
        this->crypto_driver->put_shared_secret(buf, shared_key.data(), shared_key.size());
        
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
    this->send(data);
    auto client_kex_init = std::move(data); // store for hashing

    data = this->read();
    kex_algo_recv(data, crypto_driver);
    auto server_kex_init = std::move(data);

    auto [dh, priv, pub] = crypto_driver->DH_initialize();
    
    // send client public key
    data.clear();
    data.push_back(SSH_MSG_KEXDH_INIT);
    put_integer_big(static_cast<uint32_t>(dh.PublicKeyLength()), data);
    data.insert(data.end(), pub.begin(), pub.end());
    this->send(data);

    // recv server public key
    data = this->read();
    size_t idx = 0;
    CryptoPP::byte c;
    get_integer_big(&c, data, idx);
    if (c != SSH_MSG_KEXDH_REPLY) {
        throw std::runtime_error("error state in kex_init: " + std::string(1, c));
    }

    auto sign_pk = crypto_driver->get_sign_pubkey(data, idx);
    auto server_pub = get_string(data, idx);
    auto signature = crypto_driver->get_signature(data, idx);
    shared_key = 
            crypto_driver->DH_generate_shared_key(dh, priv, 
                string_to_byteblock(server_pub));
    
    session_id = crypto_driver->get_session_id(server_banner, banner, 
                                    client_kex_init, server_kex_init, sign_pk, pub, 
                                    string_to_byteblock(server_pub), shared_key);

    key_derive();
    data = this->read();
    if (data[0] != SSH_MSG_NEWKEYS) {
        throw std::runtime_error("need rekey");
    }

    if (!crypto_driver->DSA_verify(sign_pk, session_id, signature)) {
        throw std::runtime_error("failed to verify packet");
    }

    this->send(std::vector<CryptoPP::byte>(1, SSH_MSG_NEWKEYS));
    crypto_driver->Enc_setup(
        enc_client_to_server, iv_client_to_server, enc_server_to_client, iv_server_to_client);
    kex = true;
}

std::vector<CryptoPP::byte> SSHClient::read() {
    uint32_t    packet_id = recv_packet_id++;
    if (!kex) {
        return network_driver->read();
    }

    auto data = network_driver->read(CryptoPP::AES::BLOCKSIZE);
    std::vector<CryptoPP::byte> recover;
    crypto_driver->Enc_decrypt(data, recover);

    uint32_t len;
    size_t idx = 0;
    get_integer_big(&len, recover, idx);
    auto remain = network_driver->read(len - (recover.size() - sizeof(len)));
    crypto_driver->Enc_decrypt(remain, recover);
    // hexdump("packet", recover);
    
    auto mac = network_driver->read(MAC_SIZE);
    // hexdump("mac", mac);
    std::vector<CryptoPP::byte> mac_buf;
    put_integer_big(packet_id, mac_buf);
    mac_buf.insert(mac_buf.end(), recover.begin(), recover.end());
    bool valid = crypto_driver->HMAC_verify(mac_server_to_client, 
            std::string(mac_buf.begin(), mac_buf.end()), 
                    std::string(mac.begin(), mac.end()));
    if (!valid) {
        throw std::runtime_error("mac verify failed");
    }

    Packet packet;
    packet.deserialize(recover);
    return packet.payload;
}

void SSHClient::send(const std::vector<CryptoPP::byte> &payload) {
    uint32_t    packet_id = send_packet_id++;
    uint32_t    packet_length;
    uint8_t     padding_length;
    if (!kex) {
        Packet packet;
        packet.payload = payload;
        return network_driver->send(packet.serialize());
    }
    
    uint32_t len = payload.size() + sizeof(packet_length) + sizeof(padding_length);
    padding_length = 2 * CryptoPP::AES::BLOCKSIZE - (len % CryptoPP::AES::BLOCKSIZE);
    // padding_length += (crypto_driver->png(1)[0] % 2) * AES::BLOCKSIZE;
    packet_length = sizeof(padding_length) + payload.size() + padding_length;

    std::vector<CryptoPP::byte> data;
    put_integer_big(packet_id, data);
    put_integer_big(packet_length, data);
    put_integer_big(padding_length, data);
    data.insert(data.end(), payload.begin(), payload.end());
    data.resize(sizeof(packet_length) + packet_length + sizeof(packet_id));

    auto hmac = crypto_driver->HMAC_generate(mac_client_to_server, data);
    // remove packet id
    data.erase(data.begin(), data.begin() + sizeof(packet_id));
    // encrypt
    std::vector<CryptoPP::byte> cipher;
    this->crypto_driver->Enc_encrypt(data, cipher);

    cipher.insert(cipher.end(), hmac.begin(), hmac.end());
    return network_driver->send(cipher);
}

void SSHClient::auth() {
    std::vector<CryptoPP::byte> data;
    data.push_back(SSH_MSG_SERVICE_REQUEST);
    put_string(data, "ssh-userauth");
    this->send(data);

    auto recv = this->read();
    size_t idx = 0;
    if (recv[idx++] != SSH_MSG_SERVICE_ACCEPT) {
        throw std::runtime_error("auth service failed");
    }
    auto acc = get_string(recv, idx);
    if (acc != "ssh-userauth") {
        throw std::runtime_error("auth service failed");
    }

    data.clear();
    data.push_back(SSH_MSG_USERAUTH_REQUEST);
    put_string(data, this->name);
    put_string(data, "ssh-connection");
    put_string(data, "publickey");
    data.push_back(1U); // flag for signature
    put_string(data, this->crypto_driver->get_pki_name());

    auto [priv, pub] = crypto_driver->import_auth_key(pk_file);
    crypto_driver->put_sign_pubkey(data, pub);

    std::vector<CryptoPP::byte> sign_input;
    put_string(sign_input, session_id);
    sign_input.insert(sign_input.end(), data.begin(), data.end());

    crypto_driver->put_signature(data, crypto_driver->DSA_sign(priv, sign_input));
    this->send(data);

    data = this->read();
    if (data[0] != SSH_MSG_USERAUTH_SUCCESS) {
        throw std::runtime_error("refused by server");
    }
}

void SSHClient::SendThread(uint32_t id) {
    setup_shell();
    char c;
    while (std::cin.get(c)) {
        std::vector<CryptoPP::byte> data;
        data.push_back(SSH_MSG_CHANNEL_DATA);
        put_integer_big(id, data);
        put_string(data, std::string(1, c));
        this->send(data);
    }
}

void SSHClient::run() {
    this->key_exchange();
    this->auth();
    CUSTOM_LOG(lg, debug) << "test1";
    boost::thread msgListener =
      boost::thread(boost::bind(&SSHClient::ReceiveThread, this));
    auto id = this->open_channel();
    
    // request pty & shell
    this->send(channel_request_pty(id));
    this->send(channel_request_head(id, "shell", 1));
    
    boost::thread msgInput =
      boost::thread(boost::bind(&SSHClient::SendThread, this, id));

    msgInput.detach();
    msgListener.join();

    std::vector<CryptoPP::byte> data;
    data.push_back(SSH_MSG_DISCONNECT);
    put_integer_big(id, data);
    put_string(data, "Bye bye");
    this->send(data);
    do_cleanup(0);
}

SSHClient::~SSHClient() {
    this->network_driver->disconnect();
}