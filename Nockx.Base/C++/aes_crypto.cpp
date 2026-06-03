#include "aes_crypto.h"

#include <cstdint>
#include <stdexcept>
#include <vector>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>

struct SecureKey {
	uint8_t *data;
	int len;

	SecureKey(const int n) : len(n) {
		data = static_cast<uint8_t *>(CRYPTO_secure_malloc(n, __FILE__, __LINE__));
	}

	~SecureKey() {
		CRYPTO_secure_clear_free(data, len, __FILE__, __LINE__);
	}

	SecureKey(const SecureKey &) = delete;
	SecureKey & operator=(const SecureKey &) = delete;

	SecureKey(SecureKey &&other) noexcept : data(other.data), len(other.len) {
		other.data = nullptr;
		other.len = 0;
	}

	SecureKey & operator=(SecureKey &&other) noexcept {
		if (this != &other) {
			CRYPTO_secure_clear_free(data, len, __FILE__, __LINE__);
			data = other.data;
			len = other.len;
			other.data = nullptr;
			other.len = 0;
		}

		return *this;
	}
};

struct AesKey {
	SecureKey key, iv;

	AesKey() : key(32), iv(12) {
		if (RAND_bytes(key.data, key.len) != 1 || RAND_bytes(iv.data, iv.len) != 1)
			throw std::runtime_error("RAND_bytes failed");
	}
};

AesKey *create_aes_key() {
	try {
		return new AesKey();
	} catch (...) {
		return nullptr;
	}
}

void destroy_aes_key(const AesKey *aes_key) {
	delete aes_key;
}

uint8_t encrypt_with_aes_gcm(const uint8_t *plaintext, const size_t plaintext_len, const AesKey *aes_key, const uint8_t *extra_auth_data, const size_t extra_auth_data_len, uint8_t *ciphertext) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Failed to create context:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	struct Guard {
		EVP_CIPHER_CTX *c;

		~Guard() {
			EVP_CIPHER_CTX_free(c);
		}
	} guard{ctx};

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
		fprintf(stderr, "Failed to set encryption type:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
		fprintf(stderr, "Failed to set IV length:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, aes_key->key.data, aes_key->iv.data) != 1) {
		fprintf(stderr, "Failed to set AES key:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	// Authenticate the extra data without encrypting it
	int len = 0;
	if (EVP_EncryptUpdate(ctx, nullptr, &len, extra_auth_data, static_cast<int>(extra_auth_data_len)) != 1) {
		fprintf(stderr, "Failed to authenticate extra data:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, static_cast<int>(plaintext_len)) != 1) {
		fprintf(stderr, "Failed to encrypt:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	int total = len;
	if (EVP_EncryptFinal_ex(ctx, ciphertext + total, &len) != 1) {
		fprintf(stderr, "Failed to finalize encryption:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}
	total += len;

	std::vector<uint8_t> tag(16);
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
		fprintf(stderr, "Failed to get tag:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	memcpy(ciphertext + total, tag.data(), tag.size());

	return 1;
}

uint8_t decrypt_with_aes_gcm(const uint8_t *ciphertext, const size_t ciphertext_len, const AesKey *aes_key, const uint8_t *extra_auth_data, const size_t extra_auth_data_len, uint8_t *plaintext) {
	if (ciphertext_len < 16) {
		fprintf(stderr, "Ciphertext too short\n");
		return 0;
	}

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Failed to create context:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	struct Guard {
		EVP_CIPHER_CTX *c;

		~Guard() {
			EVP_CIPHER_CTX_free(c);
		}
	} guard{ctx};

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
		fprintf(stderr, "Failed to set decryption type:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
		fprintf(stderr, "Failed to set IV length:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, aes_key->key.data, aes_key->iv.data) != 1) {
		fprintf(stderr, "Failed to set AES key:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	int len = 0;
	if (EVP_DecryptUpdate(ctx, nullptr, &len, extra_auth_data, static_cast<int>(extra_auth_data_len)) != 1) {
		fprintf(stderr, "Failed to authenticate extra data:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	const size_t actual_ciphertext_len = ciphertext_len - 16;
	if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, static_cast<int>(actual_ciphertext_len)) != 1) {
		fprintf(stderr, "Failed to decrypt:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	const int total = len;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t *>(ciphertext + actual_ciphertext_len)) != 1) {
		fprintf(stderr, "Failed to set tag:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (EVP_DecryptFinal_ex(ctx, plaintext + total, &len) <= 0) {
		fprintf(stderr, "Authentication failed. Message is corrupt or tampered:\n");
		ERR_print_errors_fp(stderr);
		OPENSSL_cleanse(plaintext, actual_ciphertext_len);  // zero out any partial plaintext
		return 0;
	}

	return 1;
}
