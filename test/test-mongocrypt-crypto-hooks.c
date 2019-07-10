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

#include "mongocrypt-private.h"
#include "mongocrypt-crypto-private.h"

#include "test-mongocrypt.h"

#define IV_HEX "1F572A1B84EC8F99B7915AA2A2AEA2F4"
#define HMAC_HEX                                                      \
   "60676DE9FD305FD2C0815763C422687270DA2416D94A917B276E9DCBB13F412F" \
   "92FA403AA8AE172BD2E4729ED352793795EE588A2977C9C1F218D2AAD779C997"
/* only the first 32 bytes are appended. */
#define HMAC_HEX_TAG \
   "60676DE9FD305FD2C0815763C422687270DA2416D94A917B276E9DCBB13F412F"

#define HMAC_KEY_HEX \
   "CCD3836C8F24AC5FAAFAAA630C5C6C5D210FD03934EA1440CD67E0DCDE3F8EA6"
#define ENCRYPTION_KEY_HEX \
   "E1D1727BAF970E01181C0868CB9D3E574B47AC09771FF30FE2D093B0950C7DAF"
#define IV_KEY_HEX \
   "0A9328FCB6405ABDF5B4BFEC243FE9CF503CD4F24360872B75F08A2A3961802B"
/* full 96 byte key consists of three "sub" keys */
#define KEY_HEX HMAC_KEY_HEX ENCRYPTION_KEY_HEX IV_KEY_HEX
#define HASH_HEX \
   "489EC3238378DC624C74B8CC4598ACED2B7EA5DE5C5F7602D8761BAE92FD8ABE"
#define RANDOM_HEX                                                             \
   "670ACBB44D4E04A279CC0B95D217493205A038C50F537F452C59EFF6541D0026670ACBB44" \
   "D4E04A279CC0B95D217493205A038C50F537F452C59EFF6541D0026670ACBB44D4E04A279" \
   "CC0B95D217493205A038C50F537F452C59EFF6541D0026"

/* a document containing the history of calls */
static bson_string_t *call_history;

static void
_append_bin (const char *name, mongocrypt_binary_t *bin)
{
   _mongocrypt_buffer_t tmp;
   char *hex;

   _mongocrypt_buffer_from_binary (&tmp, bin);
   hex = _mongocrypt_buffer_to_hex (&tmp);
   bson_string_append_printf (call_history, "%s:%s\n", name, hex);
   bson_free (hex);
   _mongocrypt_buffer_cleanup (&tmp);
}


static bool
_aes_256_cbc_encrypt (void *ctx,
                      mongocrypt_binary_t *key,
                      mongocrypt_binary_t *iv,
                      mongocrypt_binary_t *in_array,
                      uint32_t in_count,
                      mongocrypt_binary_t *out,
                      uint32_t *bytes_written,
                      mongocrypt_status_t *status)
{
   int i = 0;

   BSON_ASSERT (0 == strcmp ("context", (char *) ctx));
   bson_string_append_printf (call_history, "call:%s\n", BSON_FUNC);
   _append_bin ("key", key);
   _append_bin ("iv", iv);
   for (i = 0; i < in_count; i++) {
      _append_bin ("in", &in_array[i]);
      /* append it directly, don't encrypt. */
      memcpy (out->data + *bytes_written, in_array[i].data, in_array[i].len);
      *bytes_written += in_array[i].len;
   }
   bson_string_append_printf (call_history, "ret:%s\n", BSON_FUNC);
   return true;
}

static bool
_aes_256_cbc_decrypt (void *ctx,
                      mongocrypt_binary_t *key,
                      mongocrypt_binary_t *iv,
                      mongocrypt_binary_t *in_array,
                      uint32_t in_count,
                      mongocrypt_binary_t *out,
                      uint32_t *bytes_written,
                      mongocrypt_status_t *status)
{
   int i = 0;

   BSON_ASSERT (0 == strcmp ("context", (char *) ctx));
   bson_string_append_printf (call_history, "call:%s\n", BSON_FUNC);
   _append_bin ("key", key);
   _append_bin ("iv", iv);
   for (i = 0; i < in_count; i++) {
      _append_bin ("in", &in_array[i]);
      /* append it directly, don't decrypt. */
      memcpy (out->data + *bytes_written, in_array[i].data, in_array[i].len);
      *bytes_written += in_array[i].len;
   }
   bson_string_append_printf (call_history, "ret:%s\n", BSON_FUNC);
   return true;
}

bool
_hmac_sha_512 (void *ctx,
               mongocrypt_binary_t *key,
               mongocrypt_binary_t *in_array,
               uint32_t in_count,
               mongocrypt_binary_t *out,
               mongocrypt_status_t *status)
{
   _mongocrypt_buffer_t tmp;
   int i;

   BSON_ASSERT (0 == strcmp ("context", (char *) ctx));
   bson_string_append_printf (call_history, "call:%s\n", BSON_FUNC);
   _append_bin ("key", key);
   for (i = 0; i < in_count; i++) {
      _append_bin ("in", &in_array[i]);
   }

   bson_string_append_printf (call_history, "ret:%s\n", BSON_FUNC);

   _mongocrypt_buffer_copy_from_hex (&tmp, HMAC_HEX);
   memcpy (out->data, tmp.data, tmp.len);
   _mongocrypt_buffer_cleanup (&tmp);
   return true;
}

bool
_hmac_sha_256 (void *ctx,
               mongocrypt_binary_t *key,
               mongocrypt_binary_t *in_array,
               uint32_t in_count,
               mongocrypt_binary_t *out,
               mongocrypt_status_t *status)
{
   int i;
   _mongocrypt_buffer_t tmp;

   BSON_ASSERT (0 == strcmp ("context", (char *) ctx));
   bson_string_append_printf (call_history, "call:%s\n", BSON_FUNC);
   _append_bin ("key", key);
   for (i = 0; i < in_count; i++) {
      _append_bin ("in", &in_array[i]);
   }

   bson_string_append_printf (call_history, "ret:%s\n", BSON_FUNC);

   _mongocrypt_buffer_copy_from_hex (&tmp, HASH_HEX);
   memcpy (out->data, tmp.data, tmp.len);
   _mongocrypt_buffer_cleanup (&tmp);
   return true;
}

bool
_sha_256 (void *ctx,
          mongocrypt_binary_t *in_array,
          uint32_t in_count,
          mongocrypt_binary_t *out,
          mongocrypt_status_t *status)
{
   int i;
   _mongocrypt_buffer_t tmp;

   BSON_ASSERT (0 == strcmp ("context", (char *) ctx));
   bson_string_append_printf (call_history, "call:%s\n", BSON_FUNC);
   for (i = 0; i < in_count; i++) {
      _append_bin ("in", &in_array[i]);
   }

   bson_string_append_printf (call_history, "ret:%s\n", BSON_FUNC);

   _mongocrypt_buffer_copy_from_hex (&tmp, HASH_HEX);
   memcpy (out->data, tmp.data, tmp.len);
   _mongocrypt_buffer_cleanup (&tmp);
   return true;
}

bool
_random (void *ctx,
         mongocrypt_binary_t *out,
         uint32_t count,
         mongocrypt_status_t *status)
{
   /* only have 32 bytes of random test data. */
   BSON_ASSERT (count <= 96);

   bson_string_append_printf (call_history, "call:%s\n", BSON_FUNC);
   bson_string_append_printf (call_history, "count:%d\n", (int) count);
   bson_string_append_printf (call_history, "ret:%s\n", BSON_FUNC);

   _mongocrypt_buffer_t tmp;
   _mongocrypt_buffer_copy_from_hex (&tmp, RANDOM_HEX);
   memcpy (out->data, tmp.data, count);
   _mongocrypt_buffer_cleanup (&tmp);
   return true;
}


static mongocrypt_t *
_create_mongocrypt (void)
{
   bool ret;

   mongocrypt_t *crypt = mongocrypt_new ();
   ASSERT_OK (
      mongocrypt_setopt_kms_provider_aws (crypt, "example", -1, "example", -1),
      crypt);
   ret = mongocrypt_setopt_crypto_hooks (crypt,
                                         _aes_256_cbc_encrypt,
                                         _aes_256_cbc_decrypt,
                                         _random,
                                         _hmac_sha_512,
                                         _hmac_sha_256,
                                         _sha_256,
                                         "context");
   ASSERT_OK (ret, crypt);
   ASSERT_OK (mongocrypt_init (crypt), crypt);
   return crypt;
}


static void
_test_crypto_hooks_encryption (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   bool ret;
   uint32_t bytes_written;
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t iv, associated_data, key, plaintext, ciphertext;
   const char *expected_call_history =
      "call:_aes_256_cbc_encrypt\n"
      "key:" ENCRYPTION_KEY_HEX "\n"
      "iv:" IV_HEX "\n"
      "in:\n"
      "in:BBBB0E0E0E0E0E0E0E0E0E0E0E0E0E0E\n"
      "ret:_aes_256_cbc_encrypt\n"
      "call:_hmac_sha_512\n"
      "key:CCD3836C8F24AC5FAAFAAA630C5C6C5D210FD03934EA1440CD67E0DCDE3F8EA6\n"
      "in:AAAA\n"
      "in:" IV_HEX "BBBB0E0E0E0E0E0E0E0E0E0E0E0E0E0E\n"
      "in:0000000000000010\n"
      "ret:_hmac_sha_512\n";

   status = mongocrypt_status_new ();
   crypt = _create_mongocrypt ();

   _mongocrypt_buffer_copy_from_hex (&iv, IV_HEX);
   _mongocrypt_buffer_copy_from_hex (&associated_data, "AAAA");
   _mongocrypt_buffer_copy_from_hex (&key, KEY_HEX);
   _mongocrypt_buffer_copy_from_hex (&plaintext, "BBBB");

   _mongocrypt_buffer_init (&ciphertext);
   _mongocrypt_buffer_resize (
      &ciphertext, _mongocrypt_calculate_ciphertext_len (plaintext.len));

   call_history = bson_string_new (NULL);

   ret = _mongocrypt_do_encryption (crypt->crypto,
                                    &iv,
                                    &associated_data,
                                    &key,
                                    &plaintext,
                                    &ciphertext,
                                    &bytes_written,
                                    status);
   ASSERT_OK_STATUS (ret, status);
   ciphertext.len = bytes_written;

   /* Check the full trace. */
   BSON_ASSERT (0 == strcmp (call_history->str, expected_call_history));

   /* Check the structure of the ciphertext */
   BSON_ASSERT (0 == _mongocrypt_buffer_cmp_hex (
                        &ciphertext,
                        IV_HEX
                        "BBBB0E0E0E0E0E0E0E0E0E0E0E0E0E0E" /* the "encrypted"
                                                              block which is
                                                              really plaintext.
                                                              BBBB + padding. */
                        HMAC_HEX_TAG));

   _mongocrypt_buffer_cleanup (&key);
   _mongocrypt_buffer_cleanup (&iv);
   _mongocrypt_buffer_cleanup (&associated_data);
   _mongocrypt_buffer_cleanup (&plaintext);
   _mongocrypt_buffer_cleanup (&ciphertext);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
   bson_string_free (call_history, true);
}


static void
_test_crypto_hooks_decryption (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   bool ret;
   uint32_t bytes_written;
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t associated_data, key, plaintext, ciphertext;
   const char *expected_call_history =
      "call:_hmac_sha_512\n"
      "key:" HMAC_KEY_HEX "\n"
      "in:AAAA\n"
      "in:" IV_HEX "BBBB0E0E0E0E0E0E0E0E0E0E0E0E0E0E\n"
      "in:0000000000000010\n"
      "ret:_hmac_sha_512\n"
      "call:_aes_256_cbc_decrypt\n"
      "key:" ENCRYPTION_KEY_HEX "\n"
      "iv:" IV_HEX "\n"
      "in:BBBB0E0E0E0E0E0E0E0E0E0E0E0E0E0E\n"
      "ret:_aes_256_cbc_decrypt\n";

   status = mongocrypt_status_new ();
   crypt = _create_mongocrypt ();

   _mongocrypt_buffer_copy_from_hex (&associated_data, "AAAA");
   _mongocrypt_buffer_copy_from_hex (&key, KEY_HEX);
   _mongocrypt_buffer_copy_from_hex (
      &ciphertext, IV_HEX "BBBB0E0E0E0E0E0E0E0E0E0E0E0E0E0E" HMAC_HEX_TAG);

   _mongocrypt_buffer_init (&plaintext);
   _mongocrypt_buffer_resize (
      &plaintext, _mongocrypt_calculate_plaintext_len (ciphertext.len));

   call_history = bson_string_new (NULL);

   ret = _mongocrypt_do_decryption (crypt->crypto,
                                    &associated_data,
                                    &key,
                                    &ciphertext,
                                    &plaintext,
                                    &bytes_written,
                                    status);
   ASSERT_OK_STATUS (ret, status);
   plaintext.len = bytes_written;

   /* Check the full trace. */
   BSON_ASSERT (0 == strcmp (call_history->str, expected_call_history));

   /* Check the resulting plaintext */
   BSON_ASSERT (0 == _mongocrypt_buffer_cmp_hex (&plaintext, "BBBB"));

   _mongocrypt_buffer_cleanup (&key);
   _mongocrypt_buffer_cleanup (&associated_data);
   _mongocrypt_buffer_cleanup (&plaintext);
   _mongocrypt_buffer_cleanup (&ciphertext);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
   bson_string_free (call_history, true);
}


static void
_test_crypto_hooks_iv_gen (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   bool ret;
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t associated_data, key, plaintext, iv;
   char *expected_iv = bson_strndup (
      HMAC_HEX_TAG, 16 * 2); /* only the first 16 bytes are used for IV. */
   const char *expected_call_history = "call:_hmac_sha_512\n"
                                       "key:" IV_KEY_HEX "\n"
                                       "in:AAAA\n"
                                       "in:0000000000000010\n"
                                       "in:BBBB\n"
                                       "ret:_hmac_sha_512\n";

   status = mongocrypt_status_new ();
   crypt = _create_mongocrypt ();

   _mongocrypt_buffer_copy_from_hex (&associated_data, "AAAA");
   _mongocrypt_buffer_copy_from_hex (&key, KEY_HEX);
   _mongocrypt_buffer_copy_from_hex (&plaintext, "BBBB");

   _mongocrypt_buffer_init (&iv);
   _mongocrypt_buffer_resize (&iv, MONGOCRYPT_IV_LEN);

   call_history = bson_string_new (NULL);

   ret = _mongocrypt_calculate_deterministic_iv (
      crypt->crypto, &key, &plaintext, &associated_data, &iv, status);
   ASSERT_OK_STATUS (ret, status);

   /* Check the full trace. */
   BSON_ASSERT (0 == strcmp (call_history->str, expected_call_history));

   /* Check the resulting iv */
   BSON_ASSERT (0 == _mongocrypt_buffer_cmp_hex (&iv, expected_iv));

   bson_free (expected_iv);
   _mongocrypt_buffer_cleanup (&key);
   _mongocrypt_buffer_cleanup (&associated_data);
   _mongocrypt_buffer_cleanup (&plaintext);
   _mongocrypt_buffer_cleanup (&iv);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
   bson_string_free (call_history, true);
}


static void
_test_crypto_hooks_random (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   bool ret;
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t random;
   const char *expected_call_history = "call:_random\n"
                                       "count:96\n"
                                       "ret:_random\n";

   status = mongocrypt_status_new ();
   crypt = _create_mongocrypt ();

   _mongocrypt_buffer_init (&random);
   _mongocrypt_buffer_resize (&random, 96);

   call_history = bson_string_new (NULL);

   ret = _mongocrypt_random (crypt->crypto, &random, random.len, status);
   ASSERT_OK_STATUS (ret, status);

   /* Check the full trace. */
   BSON_ASSERT (0 == strcmp (call_history->str, expected_call_history));

   /* Check the resulting iv */
   BSON_ASSERT (0 == _mongocrypt_buffer_cmp_hex (&random, RANDOM_HEX));

   _mongocrypt_buffer_cleanup (&random);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
   bson_string_free (call_history, true);
}


static void
_test_kms_request (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   mongocrypt_ctx_t *ctx;

   status = mongocrypt_status_new ();
   crypt = _create_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);

   call_history = bson_string_new (NULL);

   ASSERT_OK (
      mongocrypt_ctx_setopt_masterkey_aws (ctx, "us-east-1", -1, "cmk", -1),
      ctx);
   ASSERT_OK (mongocrypt_ctx_datakey_init (ctx), ctx);

   /* The call history includes some random data, just assert we've called our
    * hooks. */
   BSON_ASSERT (strstr (call_history->str, "call:_hmac_sha_256"));
   BSON_ASSERT (strstr (call_history->str, "call:_sha_256"));

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
   bson_string_free (call_history, true);
}


void
_mongocrypt_tester_install_crypto_hooks (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_crypto_hooks_encryption);
   INSTALL_TEST (_test_crypto_hooks_decryption);
   INSTALL_TEST (_test_crypto_hooks_iv_gen);
   INSTALL_TEST (_test_crypto_hooks_random);
   INSTALL_TEST (_test_kms_request);
}
