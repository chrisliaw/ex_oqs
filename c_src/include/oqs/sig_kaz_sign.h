// SPDX-License-Identifier: MIT

#ifndef OQS_SIG_KAZ_SIGN_H
#define OQS_SIG_KAZ_SIGN_H

#include <oqs/oqs.h>

#if defined(OQS_ENABLE_SIG_kaz_sign_1)
#define OQS_SIG_kaz_sign_1_length_public_key 62
#define OQS_SIG_kaz_sign_1_length_secret_key 90
#define OQS_SIG_kaz_sign_1_length_signature 44

OQS_SIG *OQS_SIG_kaz_sign_1_new(void);
OQS_API OQS_STATUS OQS_SIG_kaz_sign_1_keypair(uint8_t *public_key,
                                              uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_kaz_sign_1_sign(uint8_t *signature,
                                           size_t *signature_len,
                                           const uint8_t *message,
                                           size_t message_len,
                                           const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_kaz_sign_1_verify(const uint8_t *message,
                                             size_t message_len,
                                             const uint8_t *signature,
                                             size_t signature_len,
                                             const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_kaz_sign_3)
#define OQS_SIG_kaz_sign_3_length_public_key 84
#define OQS_SIG_kaz_sign_3_length_secret_key 134
#define OQS_SIG_kaz_sign_3_length_signature 60

OQS_SIG *OQS_SIG_kaz_sign_3_new(void);
OQS_API OQS_STATUS OQS_SIG_kaz_sign_3_keypair(uint8_t *public_key,
                                              uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_kaz_sign_3_sign(uint8_t *signature,
                                           size_t *signature_len,
                                           const uint8_t *message,
                                           size_t message_len,
                                           const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_kaz_sign_3_verify(const uint8_t *message,
                                             size_t message_len,
                                             const uint8_t *signature,
                                             size_t signature_len,
                                             const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_kaz_sign_5)
#define OQS_SIG_kaz_sign_5_length_public_key 106
#define OQS_SIG_kaz_sign_5_length_secret_key 176
#define OQS_SIG_kaz_sign_5_length_signature 72

OQS_SIG *OQS_SIG_kaz_sign_5_new(void);
OQS_API OQS_STATUS OQS_SIG_kaz_sign_5_keypair(uint8_t *public_key,
                                              uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_kaz_sign_5_sign(uint8_t *signature,
                                           size_t *signature_len,
                                           const uint8_t *message,
                                           size_t message_len,
                                           const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_kaz_sign_5_verify(const uint8_t *message,
                                             size_t message_len,
                                             const uint8_t *signature,
                                             size_t signature_len,
                                             const uint8_t *public_key);
#endif

// #if defined(OQS_ENABLE_SIG_dilithium_3)
// #define OQS_SIG_dilithium_3_length_public_key 1952
// #define OQS_SIG_dilithium_3_length_secret_key 4000
// #define OQS_SIG_dilithium_3_length_signature 3293
//
// OQS_SIG *OQS_SIG_dilithium_3_new(void);
// OQS_API OQS_STATUS OQS_SIG_dilithium_3_keypair(uint8_t *public_key, uint8_t
// *secret_key); OQS_API OQS_STATUS OQS_SIG_dilithium_3_sign(uint8_t *signature,
// size_t *signature_len, const uint8_t *message, size_t message_len, const
// uint8_t *secret_key); OQS_API OQS_STATUS OQS_SIG_dilithium_3_verify(const
// uint8_t *message, size_t message_len, const uint8_t *signature, size_t
// signature_len, const uint8_t *public_key); #endif

// #if defined(OQS_ENABLE_SIG_dilithium_5)
// #define OQS_SIG_dilithium_5_length_public_key 2592
// #define OQS_SIG_dilithium_5_length_secret_key 4864
// #define OQS_SIG_dilithium_5_length_signature 4595
//
// OQS_SIG *OQS_SIG_dilithium_5_new(void);
// OQS_API OQS_STATUS OQS_SIG_dilithium_5_keypair(uint8_t *public_key, uint8_t
// *secret_key); OQS_API OQS_STATUS OQS_SIG_dilithium_5_sign(uint8_t *signature,
// size_t *signature_len, const uint8_t *message, size_t message_len, const
// uint8_t *secret_key); OQS_API OQS_STATUS OQS_SIG_dilithium_5_verify(const
// uint8_t *message, size_t message_len, const uint8_t *signature, size_t
// signature_len, const uint8_t *public_key); #endif

#endif
