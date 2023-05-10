#include <iostream>
#include <stdexcept>
#include <string>

#include "crypto++/base64.h"
#include "crypto++/dsa.h"
#include "crypto++/osrng.h"
#include "crypto++/rsa.h"
#include <crypto++/cryptlib.h>
#include <crypto++/files.h>
#include <crypto++/queue.h>

#include "util/constants.hpp"
#include "util/util.hpp"
#include "drivers/crypto_driver.hpp"

using namespace CryptoPP;

/**
 * @brief Encrypts the given message using AES and tags the ciphertext with an
 * HMAC. Outputs an HMACTagged_Wrapper as bytes.
 */
std::vector<unsigned char>
CryptoDriver::encrypt_and_tag(SecByteBlock AES_key, SecByteBlock HMAC_key,
                              Serializable *message) {
  // Serialize given message.
  std::vector<unsigned char> plaintext;
  message->serialize(plaintext);

  // Encrypt the payload, generate iv to hmac.
  std::pair<std::string, SecByteBlock> encrypted =
      this->AES_encrypt(AES_key, chvec2str(plaintext));
  std::string to_tag = std::string((const char *)encrypted.second.data(),
                                   encrypted.second.size()) +
                       encrypted.first;

  // Generate HMAC on the payload.
  HMACTagged_Wrapper msg;
  msg.payload = str2chvec(encrypted.first);
  msg.iv = encrypted.second;
  msg.mac = this->HMAC_generate(HMAC_key, to_tag);

  // Serialize the HMAC and payload.
  std::vector<unsigned char> payload_data;
  msg.serialize(payload_data);
  return payload_data;
}

/**
 * @brief Verifies that the tagged HMAC is valid on the ciphertext and decrypts
 * the given message using AES. Takes in an HMACTagged_Wrapper as bytes.
 */
std::pair<std::vector<unsigned char>, bool>
CryptoDriver::decrypt_and_verify(SecByteBlock AES_key, SecByteBlock HMAC_key,
                                 std::vector<unsigned char> ciphertext_data) {
  // Deserialize
  HMACTagged_Wrapper ciphertext;
  ciphertext.deserialize(ciphertext_data);

  // Verify HMAC
  std::string to_verify =
      std::string((const char *)ciphertext.iv.data(), ciphertext.iv.size()) +
      chvec2str(ciphertext.payload);
  bool valid = this->HMAC_verify(HMAC_key, to_verify, ciphertext.mac);

  // Decrypt
  std::string plaintext =
      this->AES_decrypt(AES_key, ciphertext.iv, chvec2str(ciphertext.payload));
  std::vector<unsigned char> plaintext_data = str2chvec(plaintext);
  return std::make_pair(plaintext_data, valid);
}

/**
 * @brief Generate DH keypair.
 */
std::tuple<DH, SecByteBlock, SecByteBlock> CryptoDriver::DH_initialize() {
  DH DH_obj(DL_P, DL_Q, DL_G);
  AutoSeededRandomPool prng;
  SecByteBlock DH_private_key(DH_obj.PrivateKeyLength());
  SecByteBlock DH_public_key(DH_obj.PublicKeyLength());
  DH_obj.GenerateKeyPair(prng, DH_private_key, DH_public_key);
  return std::make_tuple(DH_obj, DH_private_key, DH_public_key);
}

/**
 * @brief Generates a shared secret.
 */
SecByteBlock CryptoDriver::DH_generate_shared_key(
    const DH &DH_obj, const SecByteBlock &DH_private_value,
    const SecByteBlock &DH_other_public_value) {
  // TODO: implement me!
  SecByteBlock shared_key(DH_obj.AgreedValueLength());
  if(!DH_obj.Agree(shared_key, DH_private_value, DH_other_public_value)) {
    throw ::std::runtime_error("Failed to reach shared secret!");
  }
  return shared_key;
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
std::pair<std::string, SecByteBlock>
CryptoDriver::AES_encrypt(SecByteBlock key, std::string plaintext) {
  try {
    ::std::string ciphertext;
    AutoSeededRandomPool rng;
    SecByteBlock iv(AES::BLOCKSIZE);

    CBC_Mode< AES >::Encryption e;
    e.GetNextIV(rng, iv);
    e.SetKeyWithIV(key, key.size(), iv);
    
    StringSource s(plaintext, true, 
        new StreamTransformationFilter(e,
            new StringSink(ciphertext)
        ) // StreamTransformationFilter
    );
    return {ciphertext, iv};
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
std::string CryptoDriver::AES_decrypt(SecByteBlock key, SecByteBlock iv,
                                      std::string ciphertext) {
  try {
    ::std::string recovered;
    CBC_Mode< AES >::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);

    StringSource s(ciphertext, true, 
        new StreamTransformationFilter(d,
            new StringSink(recovered)
        ) // StreamTransformationFilter
    );
    return recovered;
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
std::string CryptoDriver::HMAC_generate(SecByteBlock key,
                                        std::string ciphertext) {
  try {
    ::std::string hmac;
    HMAC<SHA256> hm(key, key.size());
    
    StringSource s(ciphertext, true, new HashFilter(hm, new StringSink(hmac)));
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

/**
 * @brief Generates DSA public and private keys. This function should:
 * 1) Generate a DSA::PrivateKey and a DSA::PublicKey of size DSA_KEYSIZE
 * using a CryptoPP::AutoSeededRandomPool
 * 2) Validate keys with a level of 3, throwing a runtime error if validation
 * fails.
 * @return tuple of DSA private key and public key
 */
std::pair<DSA::PrivateKey, DSA::PublicKey> CryptoDriver::DSA_generate_keys() {
  AutoSeededRandomPool rng;
  // Generate Private Key
  DSA::PrivateKey sk;
  sk.GenerateRandomWithKeySize(rng, DSA_KEYSIZE);
  
  // Generate Public Key
  DSA::PublicKey vk;
  vk.AssignFrom(sk);
  if (!sk.Validate(rng, 3) || !vk.Validate(rng, 3)) {
    throw ::std::runtime_error("DSA key generation failed");
  }
  return {sk, vk};
}

/**
 * @brief Sign the given message with the given key. This function should:
 * 1) Initialize a DSA::Signer with the given key.
 * 2) Convert the message to a string using chvec2str.
 * 3) Use a SignerFilter to generate a signature.
 * @param signing_key DSA signing key
 * @param message message to sign
 * @return signature on message
 */
std::string CryptoDriver::DSA_sign(const DSA::PrivateKey &signing_key,
                                   std::vector<unsigned char> message) {
  AutoSeededRandomPool rng;
  ::std::string signature;

  DSA::Signer signer( signing_key );
  StringSource ss1( chvec2str(message), true, 
      new SignerFilter( rng, signer,
          new StringSink( signature )
      ) // SignerFilter
  ); // StringSource
  return signature;
}

/**
 * @brief Verify that signature is valid with the given key. This function
 * should: 1) Initialize a DSA::Verifier with the given key. 2) Convert the
 * message to a string using chvev2str, and concat the signature. 3) Use a
 * SignatureVerificationFilter to verify the signature with the given flags.
 * @param signing_key DSA verification key
 * @param message signed message
 * @return true iff signature was valid on message
 */
bool CryptoDriver::DSA_verify(const DSA::PublicKey &verification_key,
                              std::vector<unsigned char> message,
                              std::string signature) {
  const int flags = SignatureVerificationFilter::PUT_RESULT |
                    SignatureVerificationFilter::SIGNATURE_AT_END;
  bool result = false;
  DSA::Verifier verifier( verification_key );
  StringSource ss2( chvec2str(message)+signature, true,
      new SignatureVerificationFilter(
          verifier, 
          new ArraySink(
            (byte*)&result, sizeof(result)), 
          flags
          /* SIGNATURE_AT_END */
      )
  );
  return result;
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
