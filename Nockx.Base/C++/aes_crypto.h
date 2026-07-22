#ifndef NOCKX_BASE_AES_CRYPTO_H
#define NOCKX_BASE_AES_CRYPTO_H

#include <cstdint>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

struct AesKey;

extern "C" {
	EXPORT AesKey *create_aes_key();

	EXPORT void destroy_aes_key(const AesKey *aes_key);

	EXPORT uint8_t generate_iv(uint8_t *iv);

	EXPORT uint8_t encrypt_with_aes_gcm(const uint8_t *plaintext, size_t plaintext_len, const AesKey *aes_key, const uint8_t *iv, const uint8_t *extra_auth_data, size_t extra_auth_data_len, uint8_t *ciphertext);

	EXPORT uint8_t decrypt_with_aes_gcm(const uint8_t *ciphertext, size_t ciphertext_len, const AesKey *aes_key, const uint8_t *iv, const uint8_t *extra_auth_data, size_t extra_auth_data_len, uint8_t *plaintext);
}

uint8_t wrap_aes_key_with_aes_gcm(const AesKey *aes_key, const uint8_t *shared_secret, uint8_t *wrapped_key);

AesKey *unwrap_aes_key_with_aes_gcm(const uint8_t *wrapped_key, const uint8_t *shared_secret);

#endif //NOCKX_BASE_AES_CRYPTO_H
