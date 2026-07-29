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
}

std::vector<uint8_t> wrap_aes_key_with_aes_gcm(const AesKey *aes_key, const uint8_t *shared_secret);

AesKey *unwrap_aes_key_with_aes_gcm(const uint8_t *wrapped_key, const uint8_t *shared_secret);

#endif //NOCKX_BASE_AES_CRYPTO_H
