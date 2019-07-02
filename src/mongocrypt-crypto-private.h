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

#include <bson/bson.h>

#include "mongocrypt.h"
#include "mongocrypt-buffer-private.h"

#define MONGOCRYPT_KEY_LEN 96
#define MONGOCRYPT_IV_KEY_LEN 32
#define MONGOCRYPT_MAC_KEY_LEN 32
#define MONGOCRYPT_ENC_KEY_LEN 32
#define MONGOCRYPT_IV_LEN 16
#define MONGOCRYPT_HMAC_SHA512_LEN 64
#define MONGOCRYPT_HMAC_LEN 32
#define MONGOCRYPT_BLOCK_SIZE 16


typedef struct {
   bool (*encrypt_aes_256_cbc) (mongocrypt_binary_t *key,
                                mongocrypt_binary_t *iv,
                                mongocrypt_binary_t *in_array,
                                uint32_t in_count,
                                mongocrypt_binary_t *out,
                                uint32_t *bytes_written);
                                
   void *(*encrypt_aes_256_cbc_new) (mongocrypt_binary_t *key,
                                     mongocrypt_binary_t *iv,
                                     mongocrypt_status_t *status);
   bool (*encrypt_update) (void *ctx,
                           mongocrypt_binary_t *in,
                           mongocrypt_binary_t *out,
                           uint32_t *bytes_written,
                           mongocrypt_status_t *status);
   bool (*encrypt_finalize) (void *ctx,
                             mongocrypt_binary_t *out,
                             uint32_t *bytes_written,
                             mongocrypt_status_t *status);
   void (*encrypt_destroy) (void *ctx);
   void *(*decrypt_aes_256_cbc_new) (mongocrypt_binary_t *key,
                                     mongocrypt_binary_t *iv,
                                     mongocrypt_status_t *status);
   bool (*decrypt_update) (void *ctx,
                           mongocrypt_binary_t *in,
                           mongocrypt_binary_t *out,
                           uint32_t *bytes_written,
                           mongocrypt_status_t *status);
   bool (*decrypt_finalize) (void *ctx,
                             mongocrypt_binary_t *out,
                             uint32_t *bytes_written,
                             mongocrypt_status_t *status);
   void (*decrypt_destroy) (void *ctx);
   void *(*hmac_sha_512_new) (mongocrypt_binary_t *key,
                              mongocrypt_status_t *status);
   void *(*hmac_sha_256_new) (mongocrypt_binary_t *key,
                              mongocrypt_status_t *status);
   bool (*hmac_update) (void *ctx,
                        mongocrypt_binary_t *in,
                        mongocrypt_status_t *status);
   bool (*hmac_finalize) (void *ctx,
                          mongocrypt_binary_t *out,
                          mongocrypt_status_t *status);
   void (*hmac_destroy) (void *ctx);
   void *(*hash_sha_256_new) (mongocrypt_status_t *status);
   bool (*hash_update) (void *ctx,
                        mongocrypt_binary_t *in,
                        mongocrypt_status_t *status);
   bool (*hash_finalize) (void *ctx,
                          mongocrypt_binary_t *out,
                          mongocrypt_status_t *status);
   void (*hash_destroy) (void *ctx);
   bool (*random) (mongocrypt_binary_t *out,
                   uint32_t count,
                   mongocrypt_status_t *status);
} _mongocrypt_crypto_t;

void *_aes_256_cbc_new (crypto)
{
   if (crypto->use_callbacks) {
      _callback_aes_256_cbc_new (crypto, ...) // does queuing
   } else {
      _native_aes_256_cbc_new (...)
   }


   uint32_t _mongocrypt_calculate_ciphertext_len (uint32_t plaintext_len);

   uint32_t _mongocrypt_calculate_plaintext_len (uint32_t ciphertext_len);

   bool _mongocrypt_do_encryption (_mongocrypt_crypto_t * crypto,
                                   const _mongocrypt_buffer_t *iv,
                                   const _mongocrypt_buffer_t *associated_data,
                                   const _mongocrypt_buffer_t *key,
                                   const _mongocrypt_buffer_t *plaintext,
                                   _mongocrypt_buffer_t *ciphertext,
                                   uint32_t *bytes_written,
                                   mongocrypt_status_t *status);

   bool _mongocrypt_do_decryption (_mongocrypt_crypto_t * crypto,
                                   const _mongocrypt_buffer_t *associated_data,
                                   const _mongocrypt_buffer_t *key,
                                   const _mongocrypt_buffer_t *ciphertext,
                                   _mongocrypt_buffer_t *plaintext,
                                   uint32_t *bytes_written,
                                   mongocrypt_status_t *status);

   bool _mongocrypt_random (_mongocrypt_crypto_t * crypto,
                            _mongocrypt_buffer_t * out,
                            uint32_t count,
                            mongocrypt_status_t * status);

   int _mongocrypt_memcmp (
      const void *const b1, const void *const b2, size_t len);

   bool _mongocrypt_calculate_deterministic_iv (
      _mongocrypt_crypto_t * crypto,
      const _mongocrypt_buffer_t *key,
      const _mongocrypt_buffer_t *plaintext,
      const _mongocrypt_buffer_t *associated_data,
      _mongocrypt_buffer_t *out,
      mongocrypt_status_t *status);

   /* Crypto implementations must implement these functions. */

   /* This variable must be defined in implementation
      files, and must be set to true when _crypto_init
      is successful. */
   extern bool _crypto_initialized;

   void _crypto_init ();

   void _crypto_set_default_hooks (_mongocrypt_crypto_t * hooks);

#endif /* MONGOCRYPT_CRYPTO_PRIVATE_H */
