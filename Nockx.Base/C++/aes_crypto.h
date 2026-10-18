#ifndef NOCKX_BASE_AES_CRYPTO_H
#define NOCKX_BASE_AES_CRYPTO_H

#include "secure_key.h"

#include <stdexcept>
#include <vector>
#include <openssl/rand.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

#define IV_LEN 12
#define AES_KEY_LEN 32

struct AesKey {
	SecureKey key;

	// This constructor should always be called with a try/catch statement because key(AES_KEY_LEN) and itself could throw an exception, which could otherwise cause a segfault downstream
	AesKey() : key(AES_KEY_LEN) {
		if (RAND_bytes(key.data, key.len) != 1)
			throw std::runtime_error("RAND_bytes failed");
	}

	// This constructor should always be called with a try/catch statement because key(AES_KEY_LEN) could throw an exception, which could otherwise cause a segfault downstream
	AesKey(const uint8_t *raw_key) : key(AES_KEY_LEN) {
		memcpy(key.data, raw_key, AES_KEY_LEN);
	}
};

extern "C" {
	EXPORT AesKey *create_aes_key();

	EXPORT void destroy_aes_key(const AesKey *aes_key);

	EXPORT int generate_iv(uint8_t *iv);

	EXPORT uint8_t *encrypt_with_aes_gcm(const uint8_t *plaintext, size_t plaintext_len, const AesKey *aes_key, const uint8_t *iv, const uint8_t *extra_auth_data, size_t extra_auth_data_len, size_t *ciphertext_len);

	EXPORT uint8_t *decrypt_with_aes_gcm(const uint8_t *ciphertext, size_t ciphertext_len, const AesKey *aes_key, const uint8_t *iv, const uint8_t *extra_auth_data, size_t extra_auth_data_len, size_t *plaintext_len);

	EXPORT EVP_CIPHER_CTX *create_gcm_context_for_stream(uint8_t for_encryption, const AesKey *aes_key, const uint8_t *iv, const uint8_t *extra_auth_data, size_t extra_auth_data_len);

	EXPORT int gcm_stream_update(EVP_CIPHER_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out);

	EXPORT int8_t gcm_stream_final(EVP_CIPHER_CTX *ctx, uint8_t for_encryption, uint8_t *tag);

	EXPORT void gcm_stream_dispose(EVP_CIPHER_CTX *ctx);
}

#endif //NOCKX_BASE_AES_CRYPTO_H
