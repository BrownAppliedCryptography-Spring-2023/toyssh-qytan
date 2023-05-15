#include <iostream>
#include <stdexcept>
#include <string>

#include <cryptopp/base64.h>
#include <cryptopp/dsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h>
#include <cryptopp/queue.h>
#include <cryptopp/xed25519.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

#include "util/constants.hpp"
#include "util/util.hpp"
#include "drivers/crypto_driver.hpp"

using namespace CryptoPP;

/**
 * @brief Generate DH keypair.
 */
std::tuple<x25519, SecByteBlock, SecByteBlock> 
CryptoDriver::DH_initialize() {
  AutoSeededRandomPool prng;
  x25519 ecdh(prng);

  SecByteBlock priv(ecdh.PrivateKeyLength());
  SecByteBlock pub(ecdh.PublicKeyLength());
  ecdh.GenerateKeyPair(prng, priv, pub);
  return {ecdh, priv, pub};
}

/**
 * @brief Generates a shared secret.
 */
SecByteBlock CryptoDriver::DH_generate_shared_key(
    const x25519 &DH_obj, const SecByteBlock &DH_private_value,
    const SecByteBlock &DH_other_public_value) {
  
  SecByteBlock shared_key(DH_obj.AgreedValueLength());
  if(!DH_obj.Agree(shared_key, DH_private_value, DH_other_public_value)) {
    throw ::std::runtime_error("Failed to reach shared secret!");
  }
  return shared_key;
}

std::string CryptoDriver::DSA_sign(
  const std::string &pk, const std::vector<CryptoPP::byte> &input
) {
  return dsa->DSA_sign(pk, input);
}

bool CryptoDriver::DSA_verify(
    const std::string &vk, const std::string &message, 
    const std::string signature) {
  
  return dsa->DSA_verify(vk, message, signature);
}

void CryptoDriver::Enc_setup(const CryptoPP::SecByteBlock &enc_key, const CryptoPP::SecByteBlock &enc_iv,
                  const CryptoPP::SecByteBlock &dec_key, const CryptoPP::SecByteBlock &dec_iv) {
  e.SetKeyWithIV(enc_key, CryptoPP::AES::DEFAULT_KEYLENGTH, enc_iv, CryptoPP::AES::BLOCKSIZE);
  d.SetKeyWithIV(dec_key, CryptoPP::AES::DEFAULT_KEYLENGTH, dec_iv, CryptoPP::AES::BLOCKSIZE);
}

/**
 * @brief Encrypts the given plaintext.
 */
void
CryptoDriver::Enc_encrypt(const std::vector<unsigned char> &plaintext, std::vector<unsigned char> &cipher) {
  try {
    CryptoPP::VectorSource _(plaintext, true, new CryptoPP::StreamTransformationFilter(
        e, new CryptoPP::VectorSink(cipher)
    ));
  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES encryption failed.");
  }
}

/**
 * @brief Decrypts the given ciphertext.
 */
void CryptoDriver::Enc_decrypt(const std::vector<unsigned char> &ciphertext, std::vector<unsigned char> &recover) {
  try {
    CryptoPP::VectorSource _(ciphertext, true, new CryptoPP::StreamTransformationFilter(
        this->d, new CryptoPP::VectorSink(recover)
    ));
  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES decryption failed.");
  }
}

/**
 * @brief Given a ciphertext, generates an HMAC
 */
std::vector<CryptoPP::byte> CryptoDriver::HMAC_generate(SecByteBlock key,
                                        const std::vector<CryptoPP::byte> &ciphertext) {
  try {
    ::std::vector<CryptoPP::byte> hmac;
    HMAC<SHA256> hm(key, key.size());
    
    VectorSource _(ciphertext, true, new HashFilter(hm, new VectorSink(hmac)));
    return hmac;
  } catch (const CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    throw std::runtime_error("CryptoDriver HMAC generation failed.");
  }
}

/**
 * @brief Given a message and MAC, checks the MAC is valid.
 */
bool CryptoDriver::HMAC_verify(SecByteBlock key, std::string ciphertext,
                               std::string mac) {
  const int flags = HashVerificationFilter::THROW_EXCEPTION |
                    HashVerificationFilter::HASH_AT_END;
  try {
      HMAC< SHA256 > hmac(key, key.size());
      
      StringSource s(ciphertext + mac, true, 
          new HashVerificationFilter(hmac, NULL, flags)
      );
      return true;
  } catch(const CryptoPP::Exception& e) {
      std::cerr << e.what() << std::endl;
      throw std::runtime_error("CryptoDriver HMAC verification failed.");
  }
}

void CryptoDriver::put_sign_pubkey(std::vector<unsigned char> &data, 
                const std::string &pub) {
    return dsa->put_sign_pubkey(data, pub);
}

std::string CryptoDriver::get_sign_pubkey_blob_from_file(
                const std::vector<unsigned char> &data, size_t &idx) {
    return dsa->get_sign_pubkey_blob_from_file(data, idx);
}

std::string CryptoDriver::get_sign_privkey_blob_from_file(
        const std::vector<unsigned char> &data, size_t &idx) {
    return dsa->get_sign_privkey_blob_from_file(data, idx);
}

std::string CryptoDriver::get_sign_pubkey(
                const std::vector<unsigned char> &data, size_t &idx) {
    return dsa->get_sign_pubkey(data, idx);
}

std::string CryptoDriver::get_signature(
                const std::vector<unsigned char> &data, size_t &idx) {
    return dsa->get_signature(data, idx);
}

void CryptoDriver::put_signature(std::vector<unsigned char> &data, 
                const std::string &signature) {
    return dsa->put_signature(data, signature);
}

std::pair<std::string, std::string> 
CryptoDriver::import_auth_key(const std::string &file) {
    return dsa->import_auth_key(file);
}

std::string CryptoDriver::get_session_id(
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
    put_shared_secret(data, shared_key.data(), shared_key.size());

    return hash(std::string(data.begin(), data.end()));
}

std::string CryptoDriver::get_pki_name() {
  return dsa->get_name();
}

/**
 * @brief Generate a pseudorandom value using AES_RNG given a seed and an iv.
 */
SecByteBlock CryptoDriver::prg(const SecByteBlock &seed, SecByteBlock iv,
                               int size) {
  OFB_Mode<AES>::Encryption prng;
  if (iv.size() < 16) {
    iv.CleanGrow(PRG_SIZE);
  }
  prng.SetKeyWithIV(seed, seed.size(), iv, iv.size());

  SecByteBlock prg_value(size);
  prng.GenerateBlock(prg_value, prg_value.size());
  return prg_value;
}

/**
 * @brief Gets the unix timestamp rounded to the minute.
 */
Integer CryptoDriver::nowish() {
  uint64_t sec = std::chrono::duration_cast<std::chrono::seconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count();
  Integer sec_int(sec);
  return sec_int;
}

/**
 * @brief Generates a random seed of size numBytes as a byte block.
 */
SecByteBlock CryptoDriver::png(int numBytes) {
  SecByteBlock seed(numBytes);
  OS_GenerateRandomBlock(false, seed, seed.size());
  return seed;
}

/**
 * @brief Generates a SHA-256 hash of msg.
 */
std::string CryptoDriver::hash(std::string msg) {
  SHA256 hash;
  std::string encodedHex;
  HexEncoder encoder(new StringSink(encodedHex));

  // Compute hash
  StringSource _s(msg, true, new HashFilter(hash, new StringSink(encodedHex)));
  return encodedHex;
}

/*
Put SSH shared secret (bignum formated into wire format)
*/
int CryptoDriver::put_shared_secret(std::vector<unsigned char> &buf, 
                      const unsigned char *x, long long len) {

    long long pos;
    for (pos = 0; pos < len; ++pos) if (x[pos]) break;

    if (x[pos] & 0x80) {
        put_integer_big(static_cast<uint32_t>(len - pos + 1), buf);
        put_integer_big(0_u8, buf);
    }
    else {
        put_integer_big(static_cast<uint32_t>(len - pos + 0), buf);
    }
    
    while (pos < len) buf.push_back(x[pos++]);
    return len;
}

