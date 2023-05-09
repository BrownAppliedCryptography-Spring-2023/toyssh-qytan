#pragma once
#include <vector>
#include <string>
#include <functional>

#define MAC_ALGO "hmac-sha2-256"
#define MAC_SIZE 32

struct ssh_kex {
    std::string name;
    std::function<int(unsigned char *, unsigned char *, 
                        const unsigned char *)> enc;
    std::function<int(unsigned char *, unsigned char *)> dh_keypair;
    long long kem_publickeybytes;
    long long kem_ciphertextbytes;
    long long kem_bytes;
    std::function<int(unsigned char *, const unsigned char *, 
                        unsigned long long)> hash;
    long long hash_bytes;
    std::function<void (struct buf *, const unsigned char *)> buf_putkemkey;
    std::function<void(struct buf *, const unsigned char *)> buf_putpubk;
};
extern const std::vector<ssh_kex> kexs;

extern int curve25519_enc(unsigned char *, unsigned char *, const unsigned char *);
extern void curve25519_putkemkey(struct buf *, const unsigned char *);

#define sshcrypto_sign_PUBLICKEYMAX 32          /* space for ed25519 pk  */
#define sshcrypto_sign_SECRETKEYMAX 64          /* space for ed25519 sk  */
#define sshcrypto_sign_MAX          64          /* space for ed25519 sig */
#define sshcrypto_sign_BASE64PUBLICKEYMAX 69    /* space for ed25519 in base64 + 0-terminator */
#define sshcrypto_sign_BASE64PUBLICKEYMIN 69    /* space for ed25519 in base64 + 0-terminator */
#define sshcrypto_sign_NAMEMAX 12               /* space for string ssh-ed25519 + 0-terminator */

struct ssh_host_key {
    std::string name;
    std::function<int(unsigned char *, unsigned long long *,
                    const unsigned char *, unsigned long long,
                    const unsigned char *)> sign;
    std::function<int(unsigned char *, unsigned long long *,
                    const unsigned char *, unsigned long long,
                    const unsigned char *)> sign_open;
    std::function<int(unsigned char *, unsigned char *)> sign_keypair;
    unsigned char sign_publickey[sshcrypto_sign_PUBLICKEYMAX];
    long long sign_publickeybytes;
    long long sign_secretkeybytes;
    long long sign_bytes;
    const char *sign_publickeyfilename;
    const char *sign_secretkeyfilename;
    int sign_flagserver;
    int sign_flagclient;
    std::function<void(struct buf *, const unsigned char *)> buf_putsignature;
    std::function<void(struct buf *, const unsigned char *)> buf_putsignpk;
    std::function<void(struct buf *, const unsigned char *)> buf_putsignpkbase64;
    std::function<int(unsigned char *, const unsigned char *, long long)> parsesignature;
    std::function<int(unsigned char *, const unsigned char *, long long)> parsesignpk;
};
extern const std::vector<ssh_host_key> host_keys;

extern void ed25519_putsignature(struct buf *, const unsigned char *);
extern void ed25519_putsignpk(struct buf *, const unsigned char *);
extern void ed25519_putsignpkbase64(struct buf *, const unsigned char *);
extern int ed25519_parsesignpk(unsigned char *, const unsigned char *, long long);
extern int ed25519_parsesignature(unsigned char *, const unsigned char *, long long);


/* cipher + mac */
#define sshcrypto_cipher_KEYMAX 128     /* space for 2 x sha512 */

struct ssh_cipher {
    std::string name;
    std::function<int(unsigned char *, const unsigned char *,
                unsigned long long, const unsigned char *,
                const unsigned char *)> stream_xor;
    std::function<int(unsigned char *, const unsigned char *,
                unsigned long long, const unsigned char *)> auth;
    long long stream_keybytes;
    long long cipher_blockbytes;
    long long auth_bytes;
    std::function<void(buf *)> packet_put;
    std::function<int(buf *)> packet_get;
    unsigned int cryptotype;
    int flagenabled;
};
extern const std::vector<ssh_cipher> ciphers;

extern int sshcrypto_cipher_select(const unsigned char *, long long);
extern int sshcrypto_cipher_macselect(const unsigned char *, long long);
extern void sshcrypto_cipher_put(struct buf *);
extern void sshcrypto_cipher_macput(struct buf *b);
