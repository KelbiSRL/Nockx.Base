#include "dsa_crypto.h"

#include "library.h"
#include "aes_crypto.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/decoder.h>

unsigned char *sign_with_ml_dsa(const AsymmetricKey *private_key, const unsigned char *data, const uint64_t data_size, const AesKey **aes_keys, const int amount_aes_keys, uint64_t *signature_size) {
	if (!CRYPTO_secure_malloc_initialized()) {
		fprintf(stderr, "Secure heap is not initialized\n");
		return nullptr;
	}

	if (data_size <= 0 && amount_aes_keys <= 0) {
		fprintf(stderr, "No data provided\n");
		return nullptr;
	}

	if (!private_key) {
		fprintf(stderr, "Key is null\n");
		return nullptr;
	}

	const char *REQUIRED_KEY_TYPE = "ML-DSA-65";

	if (private_key->type != REQUIRED_KEY_TYPE) {
		fprintf(stderr, "Key has to be of type %s, but is of type %s\n", REQUIRED_KEY_TYPE, private_key->type.c_str());
		return nullptr;
	}

	EVP_PKEY *parsed_key = nullptr;
	OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(&parsed_key, "DER", nullptr, REQUIRED_KEY_TYPE, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, nullptr, nullptr);
	const unsigned char *key = private_key->key.data;
	size_t key_length = private_key->key.len;
	OSSL_DECODER_from_data(dctx, &key, &key_length);
	OSSL_DECODER_CTX_free(dctx);

	if (!parsed_key) {
		fprintf(stderr, "Failed to parse key:\n");
		print_openssl_errors();
		return nullptr;
	}

	// Combine data with AES keys
	size_t total_data_size = data_size;
	size_t prefix_size = strlen("&aesKey="); // real result is "&aesKey0=", but the number is added later
	for (int i = 0; i < amount_aes_keys; i++)
		total_data_size += prefix_size + std::to_string(i).length() + AES_KEY_LEN;

	auto *total_data = static_cast<uint8_t *>(CRYPTO_secure_malloc(total_data_size, __FILE__, __LINE__));
	if (!total_data) {
		fprintf(stderr, "Error allocating combined data pointer:\n");
		print_openssl_errors();
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	uint8_t *copy_pointer = total_data;
	memcpy(copy_pointer, data, data_size);
	copy_pointer += data_size;

	for (int i = 0; i < amount_aes_keys; i++) {
		std::string label = "&aesKey" + std::to_string(i) + "=";
		memcpy(copy_pointer, label.data(), label.size());
		copy_pointer += label.size();
		memcpy(copy_pointer, aes_keys[i]->key.data, AES_KEY_LEN);
		copy_pointer += AES_KEY_LEN;
	}
	// Data is combined in total_data now

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Failed to create context:\n");
		print_openssl_errors();
		EVP_PKEY_free(parsed_key);
		OPENSSL_secure_clear_free(total_data, total_data_size);
		return nullptr;
	}

	if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, parsed_key) <= 0) {
		fprintf(stderr, "Failed to initialize signing:\n");
		print_openssl_errors();
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		OPENSSL_secure_clear_free(total_data, total_data_size);
		return nullptr;
	}

	size_t sig_size;
	if (EVP_DigestSign(ctx, nullptr, &sig_size, total_data, total_data_size) <= 0) {
		fprintf(stderr, "Failed to sign (size check):\n");
		print_openssl_errors();
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		OPENSSL_secure_clear_free(total_data, total_data_size);
		return nullptr;
	}

	auto signature = static_cast<unsigned char *>(OPENSSL_malloc(sig_size));
	if (!signature) {
		fprintf(stderr, "Error allocating signature:\n");
		print_openssl_errors();
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		OPENSSL_secure_clear_free(total_data, total_data_size);
		return nullptr;
	}

	if (EVP_DigestSign(ctx, signature, &sig_size, total_data, total_data_size) <= 0) {
		fprintf(stderr, "Failed to sign:\n");
		print_openssl_errors();
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		OPENSSL_free(signature);
		OPENSSL_secure_clear_free(total_data, total_data_size);
		return nullptr;
	}

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(parsed_key);
	OPENSSL_secure_clear_free(total_data, total_data_size);

	*signature_size = sig_size;

	return signature;
}

int verify_with_ml_dsa(const unsigned char *public_key, const int key_size, const unsigned char *data, const uint64_t data_size, const AesKey **aes_keys, const int amount_aes_keys, const unsigned char *signature, const unsigned int signature_size) {
	if (!CRYPTO_secure_malloc_initialized()) {
		fprintf(stderr, "Secure heap is not initialized\n");
		return -1;
	}

	if (data_size <= 0 && amount_aes_keys <= 0) {
		fprintf(stderr, "No data provided\n");
		return -1;
	}

	EVP_PKEY *parsed_key = d2i_PUBKEY(nullptr, &public_key, key_size);
	if (!parsed_key) {
		fprintf(stderr, "Failed to parse key:\n");
		print_openssl_errors();
		return -1;
	}

	// Combine data with AES keys
	size_t total_data_size = data_size;
	size_t prefix_size = strlen("&aesKey="); // real result is "&aesKey0=", but the number is added later
	for (int i = 0; i < amount_aes_keys; i++)
		total_data_size += prefix_size + std::to_string(i).length() + AES_KEY_LEN;

	auto *total_data = static_cast<uint8_t *>(CRYPTO_secure_malloc(total_data_size, __FILE__, __LINE__));
	if (!total_data) {
		fprintf(stderr, "Error allocating combined data pointer:\n");
		print_openssl_errors();
		EVP_PKEY_free(parsed_key);
		return -1;
	}

	uint8_t *copy_pointer = total_data;
	memcpy(copy_pointer, data, data_size);
	copy_pointer += data_size;

	for (int i = 0; i < amount_aes_keys; i++) {
		std::string label = "&aesKey" + std::to_string(i) + "=";
		memcpy(copy_pointer, label.data(), label.size());
		copy_pointer += label.size();
		memcpy(copy_pointer, aes_keys[i]->key.data, AES_KEY_LEN);
		copy_pointer += AES_KEY_LEN;
	}
	// Data is combined in total_data now

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Failed to create context:\n");
		print_openssl_errors();
		EVP_PKEY_free(parsed_key);
		OPENSSL_secure_clear_free(total_data, total_data_size);
		return -1;
	}

	if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, parsed_key) <= 0) {
		fprintf(stderr, "Failed to initialize verifying:\n");
		print_openssl_errors();
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		OPENSSL_secure_clear_free(total_data, total_data_size);
		return -1;
	}

	int result = EVP_DigestVerify(ctx, signature, signature_size, total_data, total_data_size);

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(parsed_key);
	OPENSSL_secure_clear_free(total_data, total_data_size);

	if (result < 0) {
		fprintf(stderr, "Error during verification:\n");
		print_openssl_errors();
		return -1;
	}

	return result;
}
