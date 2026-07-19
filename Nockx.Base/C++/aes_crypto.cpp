#include "aes_crypto.h"

#include "secure_key.h"

#include <stdexcept>
#include <vector>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define IV_LEN 12
#define AES_KEY_LEN 32
#define TAG_LEN 16

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

uint8_t generate_iv(uint8_t *iv) {
	return RAND_bytes(iv, IV_LEN);
}

uint8_t encrypt_with_aes_gcm(const uint8_t *plaintext, const size_t plaintext_len, const AesKey *aes_key, const uint8_t *iv, const uint8_t *extra_auth_data, const size_t extra_auth_data_len, uint8_t *ciphertext) {
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

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) != 1) {
		fprintf(stderr, "Failed to set IV length:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, aes_key->key.data, iv) != 1) {
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

	std::vector<uint8_t> tag(TAG_LEN);
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag.data()) != 1) {
		fprintf(stderr, "Failed to get tag:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	memcpy(ciphertext + total, tag.data(), tag.size());

	return 1;
}

uint8_t decrypt_with_aes_gcm(const uint8_t *ciphertext, const size_t ciphertext_len, const AesKey *aes_key, const uint8_t *iv, const uint8_t *extra_auth_data, const size_t extra_auth_data_len, uint8_t *plaintext) {
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

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) != 1) {
		fprintf(stderr, "Failed to set IV length:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, aes_key->key.data, iv) != 1) {
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

	const size_t actual_ciphertext_len = ciphertext_len - TAG_LEN;
	if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, static_cast<int>(actual_ciphertext_len)) != 1) {
		fprintf(stderr, "Failed to decrypt:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	const int total = len;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, const_cast<uint8_t *>(ciphertext + actual_ciphertext_len)) != 1) {
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

// Fills wrapped_key with 60 bytes (12 byte IV, 32 byte AES key, 16 byte tag)
uint8_t wrap_aes_key_with_aes_gcm(const AesKey *aes_key, const uint8_t *shared_secret, uint8_t *wrapped_key) {
	try {
		const AesKey shared_secret_key(shared_secret);

		uint8_t iv[12];
		if (generate_iv(iv) != 1) {
			fprintf(stderr, "RAND_bytes failed\n");
			return 0;
		}

		memcpy(wrapped_key, iv, IV_LEN);
		return encrypt_with_aes_gcm(aes_key->key.data, aes_key->key.len, &shared_secret_key, iv, nullptr, 0, wrapped_key + IV_LEN);
	} catch (...) {
		return 0;
	}
}

uint8_t unwrap_aes_key_with_aes_gcm(const uint8_t *wrapped_key, const uint8_t *shared_secret, const AesKey *unwrapped_key) {
	try {
		const AesKey shared_secret_key(shared_secret);

		uint8_t iv[12];
		memcpy(iv, wrapped_key, IV_LEN);
		return decrypt_with_aes_gcm(wrapped_key + IV_LEN, AES_KEY_LEN + TAG_LEN, &shared_secret_key, iv, nullptr, 0, unwrapped_key->key.data);
	} catch (...) {
		return 0;
	}
}
