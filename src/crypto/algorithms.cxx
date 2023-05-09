// #include "crypto.h"
// #include "crypto/algorithms.hpp"

// const std::vector<ssh_kex> kexs = {
//     {   "curve25519-sha256",
//         curve25519_dh,
//         curve25519_keypair,
//         crypto_scalarmult_curve25519_BYTES,       /* pk */
//         crypto_scalarmult_curve25519_SCALARBYTES, /* sk */
//         crypto_scalarmult_curve25519_BYTES,       /* k  */
//         crypto_hash_sha256,
//         crypto_hash_sha256_BYTES,
//         curve25519_putsharedsecret,
//         curve25519_putdhpk,
//     },
// };

// const std::vector<ssh_host_key> host_keys = {
//     {   "ssh-ed25519",
//         crypto_sign_ed25519,
//         crypto_sign_ed25519_open,
//         crypto_sign_ed25519_keypair,
//         {0},
//         crypto_sign_ed25519_PUBLICKEYBYTES,
//         crypto_sign_ed25519_SECRETKEYBYTES,
//         crypto_sign_ed25519_BYTES,
//         "ssh_host_ed25519_key.pub",
//         "ssh_host_ed25519_key",
//         1,
//         1,
//         ed25519_putsignature,
//         ed25519_putsignpk,
//         ed25519_putsignpkbase64,
//         ed25519_parsesignature,
//         ed25519_parsesignpk,
//     },
// };

// const std::vector<ssh_cipher> ciphers = {
//     {   "aes256-ctr",
//         aesctr256_xor,
//         crypto_auth_hmacsha256,
//         crypto_core_aes256encrypt_KEYBYTES,
//         16,
//         crypto_auth_hmacsha256_BYTES,
//         aesctr_packet_put,
//         aesctr_packet_get,
//     },
// };

