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

#include "../mongocrypt-crypto-private.h"
#include "../mongocrypt-private.h"
#include "../mongocrypt-binary-private.h"

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonRandom.h>

bool _crypto_initialized = false;

void
_crypto_init ()
{
   _crypto_initialized = true;
}


static void *
_crypto_encrypt_aes_256_cbc_new (mongocrypt_binary_t *key,
                                 mongocrypt_binary_t *iv,
                                 mongocrypt_status_t *status)
{
   bool ret = false;
   CCCryptorRef ctx = NULL;
   CCCryptorStatus cc_status;

   cc_status = CCCryptorCreate (kCCEncrypt,
                                kCCAlgorithmAES,
                                0 /* defaults to CBC w/ no padding */,
                                key->data,
                                kCCKeySizeAES256,
                                iv->data,
                                &ctx);

   if (cc_status != kCCSuccess) {
      CLIENT_ERR ("error initializing cipher: %d", (int) cc_status);
      goto done;
   }

   ret = true;
done:
   if (!ret) {
      return NULL;
   }
   return (void *) ctx;
}


static bool
_crypto_encrypt_update (void *ctx,
                        mongocrypt_binary_t *in,
                        mongocrypt_binary_t *out,
                        uint32_t *bytes_written,
                        mongocrypt_status_t *status)
{
   bool ret = false;
   CCCryptorStatus cc_status;
   size_t bytes_written_size;

   cc_status = CCCryptorUpdate (
      ctx, in->data, in->len, out->data, out->len, &bytes_written_size);

   *bytes_written = bytes_written_size;

   if (cc_status != kCCSuccess) {
      CLIENT_ERR ("error encrypting: %d", (int) cc_status);
      goto done;
   }

   ret = true;
done:
   if (!ret) {
      return NULL;
   }
   return ret;
}


static bool
_crypto_encrypt_finalize (void *ctx,
                          mongocrypt_binary_t *out,
                          uint32_t *bytes_written,
                          mongocrypt_status_t *status)
{
   bool ret = false;
   CCCryptorStatus cc_status;
   size_t bytes_written_size;

   cc_status = CCCryptorFinal (ctx, out->data, out->len, &bytes_written_size);

   *bytes_written = bytes_written_size;

   if (cc_status != kCCSuccess) {
      CLIENT_ERR ("error finalizing: %d", (int) cc_status);
      goto done;
   }

   ret = true;
done:
   if (!ret) {
      return NULL;
   }
   return ret;
}


static void
_crypto_encrypt_destroy (void *ctx)
{
   if (ctx) {
      CCCryptorRelease (ctx);
   }
}


/* Note, the decrypt functions are almost exactly the same as the encrypt
 * functions
 * except for the kCCDecrypt and the error message. */
static void *
_crypto_decrypt_aes_256_cbc_new (mongocrypt_binary_t *key,
                                 mongocrypt_binary_t *iv,
                                 mongocrypt_status_t *status)
{
   bool ret = false;
   CCCryptorRef ctx = NULL;
   CCCryptorStatus cc_status;

   cc_status = CCCryptorCreate (kCCDecrypt,
                                kCCAlgorithmAES,
                                0 /* defaults to CBC w/ no padding */,
                                key->data,
                                kCCKeySizeAES256,
                                iv->data,
                                &ctx);

   if (cc_status != kCCSuccess) {
      CLIENT_ERR ("error initializing cipher: %d", (int) cc_status);
      goto done;
   }

   ret = true;
done:
   if (!ret) {
      return NULL;
   }
   return ctx;
}


static bool
_crypto_decrypt_update (void *ctx,
                        mongocrypt_binary_t *in,
                        mongocrypt_binary_t *out,
                        uint32_t *bytes_written,
                        mongocrypt_status_t *status)
{
   bool ret = false;
   CCCryptorStatus cc_status;
   size_t bytes_written_size;

   cc_status = CCCryptorUpdate (
      ctx, in->data, in->len, out->data, out->len, &bytes_written_size);

   *bytes_written = bytes_written_size;

   if (cc_status != kCCSuccess) {
      CLIENT_ERR ("error decrypting: %d", (int) cc_status);
      goto done;
   }

   ret = true;
done:
   if (!ret) {
      return NULL;
   }
   return ret;
}


static bool
_crypto_decrypt_finalize (void *ctx,
                          mongocrypt_binary_t *out,
                          uint32_t *bytes_written,
                          mongocrypt_status_t *status)
{
   bool ret = false;
   CCCryptorStatus cc_status;
   size_t bytes_written_size;

   cc_status = CCCryptorFinal (ctx, out->data, out->len, &bytes_written_size);

   *bytes_written = bytes_written_size;

   if (cc_status != kCCSuccess) {
      CLIENT_ERR ("error finalizing: %d", (int) cc_status);
      goto done;
   }

   ret = true;
done:
   if (!ret) {
      return NULL;
   }
   return ret;
}


static void
_crypto_decrypt_destroy (void *ctx)
{
   if (ctx) {
      CCCryptorRelease (ctx);
   }
}


/* CCHmac functions don't return errors. */
static void *
_crypto_hmac_sha_512_new (mongocrypt_binary_t *key, mongocrypt_status_t *status)
{
   CCHmacContext *ctx;

   ctx = bson_malloc0 (sizeof (*ctx));

   CCHmacInit (ctx, kCCHmacAlgSHA512, key->data, key->len);
   return ctx;
}


static bool
_crypto_hmac_update (void *ctx,
                     mongocrypt_binary_t *in,
                     mongocrypt_status_t *status)
{
   CCHmacUpdate (ctx, in->data, in->len);
   return true;
}


static bool
_crypto_hmac_finalize (void *ctx,
                       mongocrypt_binary_t *out,
                       mongocrypt_status_t *status)
{
   CCHmacFinal (ctx, out->data);
   return true;
}


static void
_crypto_hmac_destroy (void *ctx)
{
   if (ctx) {
      bson_free (ctx);
   }
}


static bool
_crypto_random (mongocrypt_binary_t *out,
                uint32_t count,
                mongocrypt_status_t *status)
{
   CCRNGStatus ret = CCRandomGenerateBytes (out->data, (size_t) count);
   if (ret != kCCSuccess) {
      CLIENT_ERR ("failed to generate random iv: %d", (int) ret);
      return false;
   }
   return true;
}


void
_crypto_set_default_hooks (_mongocrypt_crypto_t *hooks)
{
   hooks->encrypt_aes_256_cbc_new = _crypto_encrypt_aes_256_cbc_new;
   hooks->encrypt_update = _crypto_encrypt_update;
   hooks->encrypt_finalize = _crypto_encrypt_finalize;
   hooks->encrypt_destroy = _crypto_encrypt_destroy;
   hooks->decrypt_aes_256_cbc_new = _crypto_decrypt_aes_256_cbc_new;
   hooks->decrypt_update = _crypto_decrypt_update;
   hooks->decrypt_finalize = _crypto_decrypt_finalize;
   hooks->decrypt_destroy = _crypto_decrypt_destroy;
   hooks->hmac_sha_512_new = _crypto_hmac_sha_512_new;
   hooks->hmac_sha_256_new = NULL; /* implemented in KMS message. */
   hooks->hmac_update = _crypto_hmac_update;
   hooks->hmac_finalize = _crypto_hmac_finalize;
   hooks->hmac_destroy = _crypto_hmac_destroy;
   hooks->hash_sha_256_new = NULL;
   hooks->hash_update = NULL;
   hooks->hash_finalize = NULL;
   hooks->hash_destroy = NULL;
   hooks->random = _crypto_random;
}