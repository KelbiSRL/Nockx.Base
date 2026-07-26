#include "dsa_crypto.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/decoder.h>

unsigned char *sign_with_ml_dsa(const AsymmetricKey *private_key, const unsigned char *data, const uint64_t data_size, uint64_t *signature_size) {
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
		ERR_print_errors_fp(stderr);
		return nullptr;
	}

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Failed to create context:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, parsed_key) <= 0) {
		fprintf(stderr, "Failed to initialize signing:\n");
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	size_t sig_size;
	if (EVP_DigestSign(ctx, nullptr, &sig_size, data, data_size) <= 0) {
		fprintf(stderr, "Failed to sign (size check):\n");
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	auto signature = static_cast<unsigned char *>(OPENSSL_malloc(sig_size));
	if (!signature) {
		fprintf(stderr, "Error allocating signature:\n");
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	if (EVP_DigestSign(ctx, signature, &sig_size, data, data_size) <= 0) {
		fprintf(stderr, "Failed to sign:\n");
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		OPENSSL_free(signature);
		return nullptr;
	}

	*signature_size = sig_size;

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(parsed_key);

	return signature;
}

int verify_with_ml_dsa(const unsigned char *public_key, const int key_size, const unsigned char *data, const uint64_t data_size, const unsigned char *signature, const unsigned int signature_size) {
	EVP_PKEY *parsed_key = d2i_PUBKEY(nullptr, &public_key, key_size);
	if (!parsed_key) {
		fprintf(stderr, "Failed to parse key:\n");
		ERR_print_errors_fp(stderr);
		return -1;
	}

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Failed to create context:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_free(parsed_key);
		return -1;
	}

	if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, parsed_key) <= 0) {
		fprintf(stderr, "Failed to initialize verifying:\n");
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return -1;
	}

	int result = EVP_DigestVerify(ctx, signature, signature_size, data, data_size);

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(parsed_key);

	if (result < 0) {
		fprintf(stderr, "Error during verification:\n");
		ERR_print_errors_fp(stderr);
		return -1;
	}

	return result;
}
