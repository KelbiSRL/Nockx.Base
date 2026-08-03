#include "aes_crypto.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define TAG_LEN 16

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

int generate_iv(uint8_t *iv) {
	return RAND_bytes(iv, IV_LEN);
}

uint8_t *encrypt_with_aes_gcm(const uint8_t *plaintext, const size_t plaintext_len, const AesKey *aes_key, const uint8_t *iv, const uint8_t *extra_auth_data, const size_t extra_auth_data_len, size_t *ciphertext_len) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Failed to create context:\n");
		ERR_print_errors_fp(stderr);
		return nullptr;
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
		return nullptr;
	}

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) != 1) {
		fprintf(stderr, "Failed to set IV length:\n");
		ERR_print_errors_fp(stderr);
		return nullptr;
	}

	if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, aes_key->key.data, iv) != 1) {
		fprintf(stderr, "Failed to set AES key:\n");
		ERR_print_errors_fp(stderr);
		return nullptr;
	}

	// Authenticate the extra data without encrypting it
	int len = 0;
	if (EVP_EncryptUpdate(ctx, nullptr, &len, extra_auth_data, static_cast<int>(extra_auth_data_len)) != 1) {
		fprintf(stderr, "Failed to authenticate extra data:\n");
		ERR_print_errors_fp(stderr);
		return nullptr;
	}

	auto ciphertext = static_cast<unsigned char *>(OPENSSL_malloc(plaintext_len + TAG_LEN));
	if (!ciphertext) {
		fprintf(stderr, "Failed to allocate ciphertext:\n");
		ERR_print_errors_fp(stderr);
		return nullptr;
	}

	if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, static_cast<int>(plaintext_len)) != 1) {
		fprintf(stderr, "Failed to encrypt:\n");
		ERR_print_errors_fp(stderr);
		OPENSSL_free(ciphertext);
		return nullptr;
	}

	int total = len;
	if (EVP_EncryptFinal_ex(ctx, ciphertext + total, &len) != 1) {
		fprintf(stderr, "Failed to finalize encryption:\n");
		ERR_print_errors_fp(stderr);
		OPENSSL_free(ciphertext);
		return nullptr;
	}
	total += len;

	std::vector<uint8_t> tag(TAG_LEN);
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag.data()) != 1) {
		fprintf(stderr, "Failed to get tag:\n");
		ERR_print_errors_fp(stderr);
		OPENSSL_free(ciphertext);
		return nullptr;
	}

	memcpy(ciphertext + total, tag.data(), tag.size());

	*ciphertext_len = total + TAG_LEN;

	return ciphertext;
}

uint8_t *decrypt_with_aes_gcm(const uint8_t *ciphertext, const size_t ciphertext_len, const AesKey *aes_key, const uint8_t *iv, const uint8_t *extra_auth_data, const size_t extra_auth_data_len, size_t *plaintext_len) {
	if (ciphertext_len < TAG_LEN) {
		fprintf(stderr, "Ciphertext too short\n");
		return nullptr;
	}

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Failed to create context:\n");
		ERR_print_errors_fp(stderr);
		return nullptr;
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
		return nullptr;
	}

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) != 1) {
		fprintf(stderr, "Failed to set IV length:\n");
		ERR_print_errors_fp(stderr);
		return nullptr;
	}

	if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, aes_key->key.data, iv) != 1) {
		fprintf(stderr, "Failed to set AES key:\n");
		ERR_print_errors_fp(stderr);
		return nullptr;
	}

	int len = 0;
	if (EVP_DecryptUpdate(ctx, nullptr, &len, extra_auth_data, static_cast<int>(extra_auth_data_len)) != 1) {
		fprintf(stderr, "Failed to authenticate extra data:\n");
		ERR_print_errors_fp(stderr);
		return nullptr;
	}

	const size_t actual_ciphertext_len = ciphertext_len - TAG_LEN;

	// TODO: possibly secure alloc this
	auto plaintext = static_cast<unsigned char *>(OPENSSL_malloc(actual_ciphertext_len));
	if (!plaintext) {
		fprintf(stderr, "Failed to allocate plaintext:\n");
		ERR_print_errors_fp(stderr);
		return nullptr;
	}

	if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, static_cast<int>(actual_ciphertext_len)) != 1) {
		fprintf(stderr, "Failed to decrypt:\n");
		ERR_print_errors_fp(stderr);
		OPENSSL_cleanse(plaintext, len);
		OPENSSL_free(plaintext);
		return nullptr;
	}

	const int total = len;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, const_cast<uint8_t *>(ciphertext + actual_ciphertext_len)) != 1) {
		fprintf(stderr, "Failed to set tag:\n");
		ERR_print_errors_fp(stderr);
		OPENSSL_cleanse(plaintext, len);
		OPENSSL_free(plaintext);
		return nullptr;
	}

	if (EVP_DecryptFinal_ex(ctx, plaintext + total, &len) <= 0) {
		fprintf(stderr, "Authentication failed. Message is corrupt or tampered:\n");
		ERR_print_errors_fp(stderr);
		OPENSSL_cleanse(plaintext, actual_ciphertext_len);  // zero out any partial plaintext
		OPENSSL_free(plaintext);
		return nullptr;
	}

	*plaintext_len = actual_ciphertext_len;

	return plaintext;
}
