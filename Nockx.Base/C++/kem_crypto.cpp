#include "kem_crypto.h"

#include "aes_crypto.h"

#include <vector>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/decoder.h>

#define WRAPPED_KEY_LEN 60

unsigned char *encrypt_aes_key_with_ml_kem(const unsigned char *public_kem_key, const unsigned int kem_key_size, unsigned char *iv, const unsigned char *rsa_encrypted_aes_key, const unsigned int rsa_encrypted_aes_key_length, unsigned int *wrapped_encrypted_aes_key_length) {
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

	uint8_t *doubly_encrypted_aes_key;
	size_t doubly_encrypted_aes_key_len;
	try {
		auto ss_aes_key = new AesKey(shared_secret);
		if (!ss_aes_key) {
			fprintf(stderr, "Failed to create AES key\n");
			throw std::exception();
		}

		iv = static_cast<uint8_t *>(OPENSSL_malloc(IV_LEN));
		if (!iv) {
			fprintf(stderr, "Error allocating IV\n");
			throw std::exception();
		}

		if (generate_iv(iv) != 1) {
			fprintf(stderr, "Failed to generate IV\n");
			throw std::exception();
		}

		doubly_encrypted_aes_key = encrypt_with_aes_gcm(rsa_encrypted_aes_key, rsa_encrypted_aes_key_length, ss_aes_key, iv, nullptr, 0, &doubly_encrypted_aes_key_len);
	} catch (...) {
		fprintf(stderr, "Wrapping AES key with ML-KEM failed\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		OPENSSL_free(ciphertext);
		OPENSSL_secure_clear_free(shared_secret, ss_length);
		return nullptr;
	}

	if (sizeof(doubly_encrypted_aes_key_len) != 8) {
		fprintf(stderr, "doubly_encrypted_aes_key_len is not a 64-bit integer\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		OPENSSL_free(ciphertext);
		OPENSSL_secure_clear_free(shared_secret, ss_length);
		return nullptr;
	}

	auto wrapped_aes_key_pointer = static_cast<uint8_t *>(OPENSSL_malloc(8 + doubly_encrypted_aes_key_len + ct_length));
	if (!wrapped_aes_key_pointer) {
		fprintf(stderr, "Error allocating wrapped_aes_key_pointer\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		OPENSSL_free(ciphertext);
		OPENSSL_secure_clear_free(shared_secret, ss_length);
		return nullptr;
	}

	// Copy the length of the wrapped AES key to the front of the resulting array (byte by byte, little endian). This is more consistent than with memcpy
	for (int i = 0; i < 8; i++)
		wrapped_aes_key_pointer[i] = static_cast<uint8_t>(doubly_encrypted_aes_key_len >> (i*8));

	memcpy(wrapped_aes_key_pointer + 8, doubly_encrypted_aes_key, doubly_encrypted_aes_key_len);
	memcpy(wrapped_aes_key_pointer + 8 + doubly_encrypted_aes_key_len, ciphertext, ct_length);

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(parsed_key);
	OPENSSL_free(ciphertext);
	OPENSSL_secure_clear_free(shared_secret, ss_length);

	*wrapped_encrypted_aes_key_length = doubly_encrypted_aes_key_len + ct_length;

	return wrapped_aes_key_pointer;
}

unsigned char *decrypt_aes_key_with_ml_kem(const AsymmetricKey *private_kem_key, const unsigned char *ciphertext, const unsigned int ciphertext_len, const unsigned char *iv, unsigned int *plaintext_len) {
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

	size_t wrapped_encrypted_aes_key_len = 0;
	for (int i = 0; i < 8; i++)
		wrapped_encrypted_aes_key_len |= ciphertext[i] << (i*8);

	size_t ss_length;
	std::vector true_ciphertext(ciphertext + 8 + wrapped_encrypted_aes_key_len, ciphertext + ciphertext_len);
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

	AesKey *shared_secret_aes_key;
	try {
		shared_secret_aes_key = new AesKey(shared_secret);
	} catch (...) {
		fprintf(stderr, "Failed to create AesKey shared_secret_aes_key:\n");
		ERR_print_errors_fp(stderr);
		OPENSSL_secure_clear_free(shared_secret, ss_length);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	size_t local_plaintext_len;
	unsigned char *unwrapped_key = decrypt_with_aes_gcm(ciphertext + 8, wrapped_encrypted_aes_key_len, shared_secret_aes_key, iv, nullptr, 0, &local_plaintext_len);
	OPENSSL_secure_clear_free(shared_secret, ss_length);

	*plaintext_len = local_plaintext_len;

	if (!unwrapped_key)
		fprintf(stderr, "Failed to unwrap AES key\n");

	return unwrapped_key;
}