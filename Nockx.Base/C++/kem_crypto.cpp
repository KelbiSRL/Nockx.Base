#include "kem_crypto.h"

#include "aes_crypto.h"

#include <vector>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/decoder.h>

#define WRAPPED_KEY_LEN 60

unsigned char *encrypt_aes_key_with_ml_kem(const unsigned char *public_kem_key, const unsigned int kem_key_size, const AesKey *aes_key, unsigned int *wrapped_encrypted_aes_key_length) {
	EVP_PKEY *parsed_key = d2i_PUBKEY(nullptr, &public_kem_key, kem_key_size);
	if (!parsed_key) {
		fprintf(stderr, "Failed to parse key:\n");
		ERR_print_errors_fp(stderr);
		return nullptr;
	}

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(parsed_key, nullptr);
	if (!ctx) {
		fprintf(stderr, "Failed to create context:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	if (EVP_PKEY_encapsulate_init(ctx, nullptr) <= 0) {
		fprintf(stderr, "Failed to initialize encapsulation:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	size_t ct_length, ss_length;
	if (EVP_PKEY_encapsulate(ctx, nullptr, &ct_length, nullptr, &ss_length) <= 0) {
		fprintf(stderr, "Failed to encapsulate (size check):\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	auto ciphertext = static_cast<unsigned char *>(OPENSSL_malloc(ct_length));
	if (!ciphertext) {
		fprintf(stderr, "Error allocating ciphertext:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	auto shared_secret = static_cast<unsigned char *>(OPENSSL_secure_malloc(ss_length));
	if (!shared_secret) {
		fprintf(stderr, "Error allocating shared_secret:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		OPENSSL_free(ciphertext);
		return nullptr;
	}

	if (EVP_PKEY_encapsulate(ctx, ciphertext, &ct_length, shared_secret, &ss_length) <= 0) {
		fprintf(stderr, "Failed to encapsulate:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		OPENSSL_free(ciphertext);
		OPENSSL_secure_clear_free(shared_secret, ss_length);
		return nullptr;
	}

	std::vector<uint8_t> wrapped_aes_key;
	try {
		wrapped_aes_key = wrap_aes_key_with_aes_gcm(aes_key, shared_secret);
	} catch (...) {
		fprintf(stderr, "Wrapping AES key with ML-KEM failed\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		OPENSSL_free(ciphertext);
		OPENSSL_secure_clear_free(shared_secret, ss_length);
		return nullptr;
	}

	auto wrapped_aes_key_pointer = static_cast<uint8_t *>(OPENSSL_malloc(wrapped_aes_key.size() + ct_length));
	memcpy(wrapped_aes_key_pointer, wrapped_aes_key.data(), wrapped_aes_key.size());
	memcpy(wrapped_aes_key_pointer + wrapped_aes_key.size(), ciphertext, ct_length);

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(parsed_key);
	OPENSSL_free(ciphertext);
	OPENSSL_secure_clear_free(shared_secret, ss_length);

	*wrapped_encrypted_aes_key_length = wrapped_aes_key.size() + ct_length;

	return wrapped_aes_key_pointer;
}

AesKey *decrypt_aes_key_with_ml_kem(const AsymmetricKey *private_kem_key, const unsigned char *ciphertext, const unsigned int ciphertext_length) {
	if (!private_kem_key) {
		fprintf(stderr, "Key is null\n");
		return nullptr;
	}

	const char *REQUIRED_KEY_TYPE = "ML-KEM-768";

	if (private_kem_key->type != REQUIRED_KEY_TYPE) {
		fprintf(stderr, "Key has to be of type %s, but is of type %s\n", REQUIRED_KEY_TYPE, private_kem_key->type.c_str());
		return nullptr;
	}

	EVP_PKEY *parsed_key = nullptr;
	OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(&parsed_key, "DER", nullptr, "ML-KEM-768", OSSL_KEYMGMT_SELECT_PRIVATE_KEY, nullptr, nullptr);
	const unsigned char *key = private_kem_key->key.data;
	size_t key_length = private_kem_key->key.len;
	OSSL_DECODER_from_data(dctx, &key, &key_length);
	OSSL_DECODER_CTX_free(dctx);

	if (!parsed_key) {
		fprintf(stderr, "Failed to parse key:\n");
		ERR_print_errors_fp(stderr);
		return nullptr;
	}

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(parsed_key, nullptr);
	if (!ctx) {
		fprintf(stderr, "Failed to create context:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	if (EVP_PKEY_decapsulate_init(ctx, nullptr) <= 0) {
		fprintf(stderr, "Failed to initialize decapsulation:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	size_t ss_length;
	std::vector true_ciphertext(ciphertext + WRAPPED_KEY_LEN, ciphertext + ciphertext_length);
	if (EVP_PKEY_decapsulate(ctx, nullptr, &ss_length, true_ciphertext.data(), true_ciphertext.size()) <= 0) {
		fprintf(stderr, "Failed to decapsulate (size check):\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	auto shared_secret = static_cast<unsigned char *>(OPENSSL_secure_malloc(ss_length));
	if (!shared_secret) {
		fprintf(stderr, "Error allocating shared_secret:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	if (EVP_PKEY_decapsulate(ctx, shared_secret, &ss_length, true_ciphertext.data(), true_ciphertext.size()) <= 0) {
		fprintf(stderr, "Failed to decapsulate:\n");
		ERR_print_errors_fp(stderr);
		OPENSSL_secure_clear_free(shared_secret, ss_length);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(parsed_key);

	AesKey *unwrapped_key = unwrap_aes_key_with_aes_gcm(ciphertext, shared_secret);
	OPENSSL_secure_clear_free(shared_secret, ss_length);

	if (!unwrapped_key)
		fprintf(stderr, "Failed to unwrap AES key\n");

	return unwrapped_key;
}