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

#include <bcrypt.h>

static BCRYPT_ALG_HANDLE _algo_sha512_hmac = 0;
static BCRYPT_ALG_HANDLE _algo_aes256 = 0;
static DWORD _aes256_key_blob_length;

static BCRYPT_ALG_HANDLE _random;

#define STATUS_SUCCESS 0

bool _crypto_initialized = false;

void
_crypto_init ()
{
   DWORD cbOutput;
   NTSTATUS nt_status;

   nt_status = BCryptOpenAlgorithmProvider (&_algo_sha512_hmac,
                                            BCRYPT_SHA512_ALGORITHM,
                                            MS_PRIMITIVE_PROVIDER,
                                            BCRYPT_ALG_HANDLE_HMAC_FLAG);
   if (nt_status != STATUS_SUCCESS) {
      return;
   }

   nt_status = BCryptOpenAlgorithmProvider (
      &_algo_aes256, BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
   if (nt_status != STATUS_SUCCESS) {
      return;
   }

   nt_status = BCryptSetProperty (
      _algo_aes256,
      BCRYPT_CHAINING_MODE,
      (PUCHAR) (BCRYPT_CHAIN_MODE_CBC),
      (ULONG) (sizeof (wchar_t) * wcslen (BCRYPT_CHAIN_MODE_CBC)),
      0);
   if (nt_status != STATUS_SUCCESS) {
      return;
   }

   cbOutput = sizeof (_aes256_key_blob_length);
   nt_status = BCryptGetProperty (_algo_aes256,
                                  BCRYPT_OBJECT_LENGTH,
                                  (PUCHAR) (&_aes256_key_blob_length),
                                  cbOutput,
                                  &cbOutput,
                                  0);
   if (nt_status != STATUS_SUCCESS) {
      return;
   }

   nt_status = BCryptOpenAlgorithmProvider (
      &_random, BCRYPT_RNG_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
   if (nt_status != STATUS_SUCCESS) {
      return;
   }

   _crypto_initialized = true;
}

void
_crypto_destroy ()
{
   (void) BCryptCloseAlgorithmProvider (_algo_sha512_hmac, 0);
   (void) BCryptCloseAlgorithmProvider (_algo_aes256, 0);
   (void) BCryptCloseAlgorithmProvider (_random, 0);
}

typedef struct {
   unsigned char *key_object;
   uint32_t key_object_length;

   BCRYPT_KEY_HANDLE key_handle;

   unsigned char *iv;
   uint32_t iv_len;
} cng_encrypt_state;


static cng_encrypt_state *
_crypto_state_init (const _mongocrypt_buffer_t *key,
                    const _mongocrypt_buffer_t *iv,
                    mongocrypt_status_t *status)
{
   cng_encrypt_state *state;
   uint32_t keyBlobLength;
   unsigned char *keyBlob;
   BCRYPT_KEY_DATA_BLOB_HEADER blobHeader;
   NTSTATUS nt_status;

   keyBlob = NULL;

   state = bson_malloc0 (sizeof (*state));
   state->key_handle = INVALID_HANDLE_VALUE;

   /* Initialize key storage buffer */
   state->key_object = bson_malloc0 (_aes256_key_blob_length);
   state->key_object_length = _aes256_key_blob_length;

   /* Allocate temporary buffer for key import */
   keyBlobLength = sizeof (BCRYPT_KEY_DATA_BLOB_HEADER) + key->len;
   keyBlob = bson_malloc0 (keyBlobLength);

   blobHeader.dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
   blobHeader.dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
   blobHeader.cbKeyData = key->len;

   memcpy (keyBlob, &blobHeader, sizeof (BCRYPT_KEY_DATA_BLOB_HEADER));

   memcpy (keyBlob + sizeof (BCRYPT_KEY_DATA_BLOB_HEADER), key->data, key->len);

   nt_status = BCryptImportKey (_algo_aes256,
                                NULL,
                                BCRYPT_KEY_DATA_BLOB,
                                &(state->key_handle),
                                state->key_object,
                                state->key_object_length,
                                keyBlob,
                                keyBlobLength,
                                0);
   if (nt_status != STATUS_SUCCESS) {
      CLIENT_ERR ("Import Key Failed: 0x%x", (int) nt_status);
      goto fail;
   }

   bson_free (keyBlob);

   state->iv = bson_malloc0 (iv->len);
   state->iv_len = iv->len;
   memcpy (state->iv, iv->data, iv->len);

   return state;
fail:
   _crypto_encrypt_destroy (state);
   bson_free (keyBlob);

   return NULL;
}


static void
_crypto_state_destroy (cng_encrypt_state *state)
{
   if (state) {
      /* Free the key handle before the key_object that contains it */
      if (state->key_handle != INVALID_HANDLE_VALUE) {
         BCryptDestroyKey (state->key_handle);
      }

      bson_free (state->key_object);
      bson_free (state->iv);
      bson_free (state);
   }
}

void *
_crypto_encrypt_new (const _mongocrypt_buffer_t *key,
                     const _mongocrypt_buffer_t *iv,
                     mongocrypt_status_t *status)
{
   return _crypto_state_init (key, iv, status);
}


bool
_crypto_encrypt_update (void *ctx,
                        const _mongocrypt_buffer_t *in,
                        _mongocrypt_buffer_t *out,
                        uint32_t *bytes_written,
                        mongocrypt_status_t *status)
{
   cng_encrypt_state *state;
   NTSTATUS nt_status;

   state = (cng_encrypt_state *) ctx;
   nt_status = BCryptEncrypt (state->key_handle,
                              (PUCHAR) (in->data),
                              in->len,
                              NULL,
                              state->iv,
                              state->iv_len,
                              out->data,
                              out->len,
                              bytes_written,
                              0);

   if (nt_status != STATUS_SUCCESS) {
      CLIENT_ERR ("error initializing cipher: 0x%x", (int) nt_status);
      return false;
   }

   return true;
}


bool
_crypto_encrypt_finalize (void *ctx,
                          _mongocrypt_buffer_t *out,
                          uint32_t *bytes_written,
                          mongocrypt_status_t *status)
{
   /* No finalize needed */
   *bytes_written = 0;
   return true;
}


void
_crypto_encrypt_destroy (void *ctx)
{
   if (ctx) {
      _crypto_state_destroy ((cng_encrypt_state *) ctx);
   }
}


void *
_crypto_decrypt_new (const _mongocrypt_buffer_t *key,
                     const _mongocrypt_buffer_t *iv,
                     mongocrypt_status_t *status)
{
   return _crypto_state_init (key, iv, status);
}


bool
_crypto_decrypt_update (void *ctx,
                        const _mongocrypt_buffer_t *in,
                        _mongocrypt_buffer_t *out,
                        uint32_t *bytes_written,
                        mongocrypt_status_t *status)
{
   cng_encrypt_state *state;
   NTSTATUS nt_status;

   state = (cng_encrypt_state *) ctx;

   nt_status = BCryptDecrypt (state->key_handle,
                              (PUCHAR) (in->data),
                              in->len,
                              NULL,
                              state->iv,
                              state->iv_len,
                              out->data,
                              out->len,
                              bytes_written,
                              0);

   if (nt_status != STATUS_SUCCESS) {
      CLIENT_ERR ("error initializing cipher: 0x%x", (int) nt_status);
      return false;
   }

   return true;
}


bool
_crypto_decrypt_finalize (void *ctx,
                          _mongocrypt_buffer_t *out,
                          uint32_t *bytes_written,
                          mongocrypt_status_t *status)
{
   /* No finalize needed */
   *bytes_written = 0;
   return true;
}


void
_crypto_decrypt_destroy (void *ctx)
{
   if (ctx) {
      _crypto_state_destroy ((cng_encrypt_state *) ctx);
   }
}

void *
_crypto_hmac_new (const _mongocrypt_buffer_t *key, mongocrypt_status_t *status)
{
   BCRYPT_HASH_HANDLE hHash;
   NTSTATUS nt_status;

   nt_status = BCryptCreateHash (_algo_sha512_hmac,
                                 &hHash,
                                 NULL,
                                 0,
                                 (PUCHAR) key->data,
                                 (ULONG) key->len,
                                 0);
   if (nt_status != STATUS_SUCCESS) {
      CLIENT_ERR ("error initializing hmac: 0x%x", (int) nt_status);
      return NULL;
   }

   return hHash;
}


bool
_crypto_hmac_update (void *ctx,
                     const _mongocrypt_buffer_t *in,
                     mongocrypt_status_t *status)
{
   BCRYPT_HASH_HANDLE hHash;
   NTSTATUS nt_status;

   hHash = (BCRYPT_HASH_HANDLE) ctx;

   nt_status = BCryptHashData (hHash, (PUCHAR) in->data, (ULONG) in->len, 0);
   if (nt_status != STATUS_SUCCESS) {
      CLIENT_ERR ("error hashing data: 0x%x", (int) nt_status);
      return false;
   }

   return true;
}


bool
_crypto_hmac_finalize (void *ctx,
                       _mongocrypt_buffer_t *out,
                       uint32_t *bytes_written,
                       mongocrypt_status_t *status)
{
   BCRYPT_HASH_HANDLE hHash;
   NTSTATUS nt_status;

   hHash = (BCRYPT_HASH_HANDLE) ctx;

   nt_status = BCryptFinishHash (hHash, out->data, out->len, 0);
   if (nt_status != STATUS_SUCCESS) {
      CLIENT_ERR ("error finishing hmac: 0x%x", (int) nt_status);
      return false;
   }

   return true;
}


void
_crypto_hmac_destroy (void *ctx)
{
   BCRYPT_HASH_HANDLE hHash;

   if (ctx) {
      hHash = (BCRYPT_HASH_HANDLE) ctx;
      (void) BCryptDestroyHash (hHash);
   }
}


bool
_crypto_random (_mongocrypt_buffer_t *out,
                mongocrypt_status_t *status,
                uint32_t count)
{
   NTSTATUS nt_status = BCryptGenRandom (_random, out->data, count, 0);
   if (nt_status != STATUS_SUCCESS) {
      CLIENT_ERR ("BCryptGenRandom Failed: 0x%x", (int) nt_status);
      return false;
   }

   return true;
}
