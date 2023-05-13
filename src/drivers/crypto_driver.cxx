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
CryptoDriver::curve25519_initialize() {
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
SecByteBlock CryptoDriver::curve25519_generate_shared_key(
    const x25519 &DH_obj, const SecByteBlock &DH_private_value,
    const SecByteBlock &DH_other_public_value) {
  
  SecByteBlock shared_key(DH_obj.AgreedValueLength());
  if(!DH_obj.Agree(shared_key, DH_private_value, DH_other_public_value)) {
    throw ::std::runtime_error("Failed to reach shared secret!");
  }
  return shared_key;
}

bool CryptoDriver::ed25519_verify(
    const std::string &vk, const std::string &message, 
    const std::string signature) {
  
  ed25519::Verifier verifier(string_to_byteblock(vk));
  return verifier.VerifyMessage(
    reinterpret_cast<const unsigned char *>(message.data()), message.size(), 
    reinterpret_cast<const unsigned char *>(signature.data()), signature.size());
}
/**
 * @brief Generates AES key using HKDF with a salt.
 */
SecByteBlock CryptoDriver::AES_generate_key(const SecByteBlock &DH_shared_key) {
  std::string aes_salt_str("salt0000");
  SecByteBlock aes_salt((const unsigned char *)(aes_salt_str.data()),
                        aes_salt_str.size());

  SecByteBlock key(AES::DEFAULT_KEYLENGTH);
  HKDF<SHA256> hkdf;
  hkdf.DeriveKey(key, key.size(), DH_shared_key, DH_shared_key.size(), 
                  aes_salt, aes_salt.size(), nullptr, 0);
  return key;
}

/**
 * @brief Encrypts the given plaintext.
 */
void
CryptoDriver::AES_encrypt(const std::vector<unsigned char> &plaintext, std::vector<unsigned char> &cipher) {
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
void CryptoDriver::AES_decrypt(const std::vector<unsigned char> &ciphertext, std::vector<unsigned char> &recover) {
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
 * @brief Generates an HMAC key using HKDF with a salt.
 */
SecByteBlock
CryptoDriver::HMAC_generate_key(const SecByteBlock &DH_shared_key) {
  std::string hmac_salt_str("salt0001");
  SecByteBlock hmac_salt((const unsigned char *)(hmac_salt_str.data()),
                         hmac_salt_str.size());
  SecByteBlock key(SHA256::BLOCKSIZE);
  HKDF<SHA256> hkdf;
  hkdf.DeriveKey(key, key.size(), DH_shared_key, DH_shared_key.size(), 
                  hmac_salt, hmac_salt.size(), nullptr, 0);
  return key;
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

void CryptoDriver::Enc_Setup(const CryptoPP::SecByteBlock &enc_key, const CryptoPP::SecByteBlock &enc_iv,
                  const CryptoPP::SecByteBlock &dec_key, const CryptoPP::SecByteBlock &dec_iv) {
  e.SetKeyWithIV(enc_key, CryptoPP::AES::DEFAULT_KEYLENGTH, enc_iv, CryptoPP::AES::BLOCKSIZE);
  d.SetKeyWithIV(dec_key, CryptoPP::AES::DEFAULT_KEYLENGTH, dec_iv, CryptoPP::AES::BLOCKSIZE);
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

void CryptoDriver::algo_select(std::string& choices, ALGO_TYPE::T) {
  // currently do not need select
}

