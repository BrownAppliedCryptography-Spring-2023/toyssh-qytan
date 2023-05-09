#pragma once
#include <vector>
#include <string>
#include <functional>

#include "sshcrypto.h"

#define MAC_ALGO "hmac-sha2-256"
#define MAC_SIZE 32

// struct ssh_kex {
//     std::string name;
//     std::function<int(unsigned char *, unsigned char *, 
//                         unsigned char *)> enc;
//     std::function<int(unsigned char *, unsigned char *)> dh_keypair;
//     long long kem_publickeybytes;
//     long long kem_ciphertextbytes;
//     long long kem_bytes;
//     std::function<int(unsigned char *, const unsigned char *, 
//                         unsigned long long)> hash;
//     long long hash_bytes;
//     std::function<void (struct buf *, const unsigned char *)> buf_putkemkey;
//     std::function<void(struct buf *, const unsigned char *)> buf_putpubk;
// };
// extern const std::vector<ssh_kex> kexs;

// struct ssh_host_key {
//     std::string name;
//     std::function<int(unsigned char *, unsigned long long *,
//                     const unsigned char *, unsigned long long,
//                     const unsigned char *)> sign;
//     std::function<int(unsigned char *, unsigned long long *,
//                     const unsigned char *, unsigned long long,
//                     const unsigned char *)> sign_open;
//     std::function<int(unsigned char *, unsigned char *)> sign_keypair;
//     unsigned char sign_publickey[sshcrypto_sign_PUBLICKEYMAX];
//     long long sign_publickeybytes;
//     long long sign_secretkeybytes;
//     long long sign_bytes;
//     const char *sign_publickeyfilename;
//     const char *sign_secretkeyfilename;
//     int sign_flagserver;
//     int sign_flagclient;
//     std::function<void(struct buf *, const unsigned char *)> buf_putsignature;
//     std::function<void(struct buf *, const unsigned char *)> buf_putsignpk;
//     std::function<void(struct buf *, const unsigned char *)> buf_putsignpkbase64;
//     std::function<int(unsigned char *, const unsigned char *, long long)> parsesignature;
//     std::function<int(unsigned char *, const unsigned char *, long long)> parsesignpk;
// };
// extern const std::vector<ssh_host_key> host_keys;


// /* cipher + mac */
// #define sshcrypto_cipher_KEYMAX 128     /* space for 2 x sha512 */

// struct ssh_cipher {
//     std::string name;
//     std::function<int(unsigned char *, const unsigned char *,
//                 unsigned long long, const unsigned char *,
//                 const unsigned char *)> stream_xor;
//     std::function<int(unsigned char *, const unsigned char *,
//                 unsigned long long, const unsigned char *)> auth;
//     long long stream_keybytes;
//     long long cipher_blockbytes;
//     long long auth_bytes;
//     std::function<void(buf *)> packet_put;
//     std::function<int(buf *)> packet_get;
// };
// extern const std::vector<ssh_cipher> ciphers;
