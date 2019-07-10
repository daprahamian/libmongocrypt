/*
 * Copyright 2019-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MONGOCRYPT_CRYPTO_PRIVATE_H
#define MONGOCRYPT_CRYPTO_PRIVATE_H

#include "mongocrypt-private.h"

#define MONGOCRYPT_KEY_LEN 96
#define MONGOCRYPT_IV_KEY_LEN 32
#define MONGOCRYPT_MAC_KEY_LEN 32
#define MONGOCRYPT_ENC_KEY_LEN 32
#define MONGOCRYPT_IV_LEN 16
#define MONGOCRYPT_HMAC_SHA512_LEN 64
#define MONGOCRYPT_HMAC_LEN 32
#define MONGOCRYPT_BLOCK_SIZE 16

typedef struct {
   int hook_placeholder;
} _mongocrypt_crypto_t;

uint32_t
_mongocrypt_calculate_ciphertext_len (uint32_t plaintext_len);

uint32_t
_mongocrypt_calculate_plaintext_len (uint32_t ciphertext_len);

bool
_mongocrypt_do_encryption (_mongocrypt_crypto_t *crypto,
                           const _mongocrypt_buffer_t *iv,
                           const _mongocrypt_buffer_t *associated_data,
                           const _mongocrypt_buffer_t *key,
                           const _mongocrypt_buffer_t *plaintext,
                           _mongocrypt_buffer_t *ciphertext,
                           uint32_t *bytes_written,
                           mongocrypt_status_t *status);

bool
_mongocrypt_do_decryption (_mongocrypt_crypto_t *crypto,
                           const _mongocrypt_buffer_t *associated_data,
                           const _mongocrypt_buffer_t *key,
                           const _mongocrypt_buffer_t *ciphertext,
                           _mongocrypt_buffer_t *plaintext,
                           uint32_t *bytes_written,
                           mongocrypt_status_t *status);

bool
_mongocrypt_random (_mongocrypt_crypto_t *crypto,
                    _mongocrypt_buffer_t *out,
                    mongocrypt_status_t *status,
                    uint32_t count);

int
_mongocrypt_memcmp (const void *const b1, const void *const b2, size_t len);

bool
_mongocrypt_calculate_deterministic_iv (
   _mongocrypt_crypto_t *crypto,
   const _mongocrypt_buffer_t *key,
   const _mongocrypt_buffer_t *plaintext,
   const _mongocrypt_buffer_t *associated_data,
   _mongocrypt_buffer_t *out,
   mongocrypt_status_t *status);

/* Crypto implementations must implement these functions. */

/* This variable must be defined in implementation
   files, and must be set to true when _crypto_init
   is successful. */
extern bool _native_crypto_initialized;

void
_native_crypto_native_init ();


bool
_native_crypto_aes_256_cbc_encrypt (const _mongocrypt_buffer_t *key,
                                    const _mongocrypt_buffer_t *iv,
                                    _mongocrypt_buffer_t *in_array,
                                    uint32_t in_count,
                                    _mongocrypt_buffer_t *out,
                                    uint32_t *bytes_written,
                                    mongocrypt_status_t *status);

bool
_native_crypto_aes_256_cbc_decrypt (const _mongocrypt_buffer_t *key,
                                    _mongocrypt_buffer_t *in_array,
                                    uint32_t in_count,
                                    _mongocrypt_buffer_t *out,
                                    uint32_t *bytes_written,
                                    mongocrypt_status_t *status);

bool
_native_crypto_hmac_sha_512 (const _mongocrypt_buffer_t *key,
                             _mongocrypt_buffer_t *in_array,
                             uint32_t in_count,
                             _mongocrypt_buffer_t *out,
                             mongocrypt_status_t *status);

bool
_native_crypto_random (_mongocrypt_buffer_t *out,
                       uint32_t count,
                       mongocrypt_status_t *status);

#endif /* MONGOCRYPT_CRYPTO_PRIVATE_H */
