#include <cryptopp/base64.h>
#include "drivers/ed25519_driver.hpp"
#include "util/util.hpp"
#include "util/constants.hpp"

std::string ED25519::get_name() {
    return "ssh-ed25519";
}

std::pair<std::string, std::string> 
ED25519::import_auth_key(const std::string &file) {
    std::ifstream priv_file(file);
    std::stringstream strStream;
    strStream << priv_file.rdbuf();
    priv_file.close();

    auto cipher = strStream.str();
    int cmp = strncmp(cipher.data(), OPENSSH_HEADER_BEGIN, strlen(OPENSSH_HEADER_BEGIN));
    if (cmp != 0) {
        std::cerr << "no header" << std::endl;
    }
    size_t idx = strlen(OPENSSH_HEADER_BEGIN);
    size_t end = cipher.find(OPENSSH_HEADER_END);
    if (end == std::string::npos) {
        std::cerr << "no tail" << std::endl;
    }

    std::vector<CryptoPP::byte> base64;
    while (idx < end) {
        auto c = cipher[idx++];
        if (!std::isspace(c)) {
            base64.push_back(c);
        }
    }

    std::vector<CryptoPP::byte> data;
    CryptoPP::Base64Decoder decoder(new CryptoPP::VectorSink(data));
    decoder.Put(base64.data(), base64.size());
    decoder.MessageEnd();

    // OpenSSH private key format
    idx = strlen(OPENSSH_AUTH_MAGIC) + 4; // openssh header

    // do not support passphrase, skip it
    idx += 2 * (4 + 4) + 1;

    uint32_t nkey;

    get_integer_little(&nkey, data, idx);
    if (nkey != 1) {
        throw std::runtime_error("only support 1 key in a file currently");
    }

    auto pub = get_sign_pubkey_blob_from_file(data, idx);
    auto priv = get_sign_privkey_blob_from_file(data, idx);
    return {priv, pub};
}

std::string ED25519::DSA_sign(
        const std::string &pk, const std::vector<CryptoPP::byte> &input) {
    CryptoPP::ed25519::Signer signer(string_to_byteblock(pk));
    CryptoPP::AutoSeededRandomPool prng;
    if (!signer.GetPrivateKey().Validate(prng, 3)) {
        throw std::runtime_error("Load private key failed");
    }

    std::string signature;

    CryptoPP::VectorSource _(input, true, new CryptoPP::SignerFilter(
        prng, signer, 
        new CryptoPP::StringSink(signature)
    ));
    return signature;
}

bool ED25519::DSA_verify(const std::string &vk, const std::string &message, const std::string signature) {
    CryptoPP::ed25519::Verifier verifier(string_to_byteblock(vk));
    return verifier.VerifyMessage(
    reinterpret_cast<const unsigned char *>(message.data()), message.size(), 
    reinterpret_cast<const unsigned char *>(signature.data()), signature.size());
}

std::string ED25519::get_sign_pubkey_blob_from_file(const std::vector<unsigned char> &data, size_t &idx) {
    uint32_t len;
    get_integer_little(&len, data, idx);
    auto algo_name = get_string_from_file(data, idx);
    assert(algo_name == "ssh-ed25519");
    return get_string_from_file(data, idx);
}

std::string ED25519::get_sign_privkey_blob_from_file(
        const std::vector<unsigned char> &data, size_t &idx) {
    uint32_t len, checkint1, checkint2;
    get_integer_little(&len, data, idx);
    get_integer_little(&checkint1, data, idx);
    get_integer_little(&checkint2, data, idx);
    if (checkint1 != checkint2) {
        throw std::runtime_error("OpenSSH private key unpack error");
    }

    auto algo_name = get_string_from_file(data, idx);
    assert(algo_name == "ssh-ed25519");
    get_string_from_file(data, idx);          // public key first
    auto priv = get_string_from_file(data, idx);

    // if (idx < data.size()) {
    //     // comment
    //     CUSTOM_LOG(lg, info) << "find private key for " << get_string_from_file(data, idx);
    // }
    return priv;
}

std::string ED25519::get_sign_pubkey(
        const std::vector<unsigned char> &data, size_t &idx) {
    uint32_t len;
    get_integer_big(&len, data, idx);
    auto algo_name = get_string(data, idx);
    assert(algo_name == "ssh-ed25519");
    return get_string(data, idx);
}

void ED25519::put_sign_pubkey(
        std::vector<unsigned char> &data, const std::string &pub) {
    std:: string algo_name = "ssh-ed25519";
    uint32_t len = algo_name.size() + 32 + 8;
    put_integer_big(len, data);
    put_string(data, algo_name);
    put_string(data, pub);
}

std::string ED25519::get_signature(
        const std::vector<unsigned char> &data, size_t &idx) {
    uint32_t len;
    get_integer_big(&len, data, idx);
    auto algo_name = get_string(data, idx);
    assert(algo_name == "ssh-ed25519");
    return get_string(data, idx);
}

void ED25519::put_signature(
        std::vector<unsigned char> &data, const std::string &signature) {
    std:: string algo_name = "ssh-ed25519";
    uint32_t len = algo_name.size() + 64 + 8;
    put_integer_big(len, data);
    put_string(data, algo_name);
    put_string(data, signature);
}

