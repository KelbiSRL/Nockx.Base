#include "rsa_crypto.h"

#include "aes_crypto.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>

unsigned char *encrypt_aes_key_with_rsa(const unsigned char *public_rsa_key, const unsigned int key_size, const AesKey *aes_key, unsigned int *ciphertext_length) {
	EVP_PKEY *parsed_key = d2i_PUBKEY(nullptr, &public_rsa_key, key_size);
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

	if (EVP_PKEY_encrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 || EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
		fprintf(stderr, "Failed to initialize encryption:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	size_t out_len;
	if (EVP_PKEY_encrypt(ctx, nullptr, &out_len, aes_key->key.data, aes_key->key.len) <= 0) {
		fprintf(stderr, "Failed to encrypt (size check):\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	auto ciphertext = static_cast<unsigned char *>(OPENSSL_malloc(out_len));
	if (!ciphertext) {
		fprintf(stderr, "Allocation failed\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	if (EVP_PKEY_encrypt(ctx, ciphertext, &out_len, aes_key->key.data, aes_key->key.len) <= 0) {
		fprintf(stderr, "Failed to encrypt:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		OPENSSL_free(ciphertext);
		return nullptr;
	}

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(parsed_key);

	*ciphertext_length = out_len;
	return ciphertext;
}

AesKey *decrypt_aes_key_with_rsa(const AsymmetricKey *private_rsa_key, const unsigned char *ciphertext, const unsigned int ciphertext_length) {
	if (!private_rsa_key) {
		fprintf(stderr, "Key is null\n");
		return nullptr;
	}

	const char *REQUIRED_KEY_TYPE = "RSA";

	if (private_rsa_key->type != REQUIRED_KEY_TYPE) {
		fprintf(stderr, "Key has to be of type %s, but is of type %s\n", REQUIRED_KEY_TYPE, private_rsa_key->type.c_str());
		return nullptr;
	}

	const int nid = OBJ_txt2nid(private_rsa_key->type.c_str());
	if (nid == NID_undef) {
		fprintf(stderr, "Unrecognized key type: %s\n", private_rsa_key->type.c_str());
		return nullptr;
	}

	const uint8_t *p = private_rsa_key->key.data;
	EVP_PKEY *parsed_key = d2i_PrivateKey(nid, nullptr, &p, private_rsa_key->key.len);
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

	if (EVP_PKEY_decrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 || EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
		fprintf(stderr, "Failed to initialize decryption:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	size_t out_len;
	if (EVP_PKEY_decrypt(ctx, nullptr, &out_len, ciphertext, ciphertext_length) <= 0) {
		fprintf(stderr, "Failed to decrypt (size check):\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	auto raw_aes_key = static_cast<unsigned char *>(OPENSSL_secure_malloc(out_len));
	if (!raw_aes_key) {
		fprintf(stderr, "Error allocating raw_key:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	if (EVP_PKEY_decrypt(ctx, raw_aes_key, &out_len, ciphertext, ciphertext_length) <= 0) {
		fprintf(stderr, "Failed to decrypt:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		OPENSSL_secure_clear_free(raw_aes_key, out_len);
		return nullptr;
	}

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(parsed_key);

	if (out_len != AES_KEY_LEN) {
		fprintf(stderr, "Decrypted key has unexpected length\n");
		OPENSSL_secure_clear_free(raw_aes_key, out_len);
		return nullptr;
	}

	AesKey *result = nullptr;
	try {
		result = new AesKey(raw_aes_key);
	} catch (...) {
		fprintf(stderr, "Error creating AesKey\n");
		result = nullptr;
	}

	OPENSSL_secure_clear_free(raw_aes_key, out_len);
	return result;
}

unsigned char *sign_with_rsa(const AsymmetricKey *private_rsa_key, const unsigned char *data, const uint64_t data_size, uint64_t *signature_size) {
	if (!private_rsa_key) {
		fprintf(stderr, "Key is null\n");
		return nullptr;
	}

	const char *REQUIRED_KEY_TYPE = "RSA";

	if (private_rsa_key->type != REQUIRED_KEY_TYPE) {
		fprintf(stderr, "Key has to be of type %s, but is of type %s\n", REQUIRED_KEY_TYPE, private_rsa_key->type.c_str());
		return nullptr;
	}

	const int nid = OBJ_txt2nid(private_rsa_key->type.c_str());
	if (nid == NID_undef) {
		fprintf(stderr, "Unrecognized key type: %s\n", private_rsa_key->type.c_str());
		return nullptr;
	}

	const uint8_t *p = private_rsa_key->key.data;
	EVP_PKEY *parsed_key = d2i_PrivateKey(nid, nullptr, &p, private_rsa_key->key.len);
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

	EVP_PKEY_CTX *pkey_ctx = nullptr;
	if (EVP_DigestSignInit(ctx, &pkey_ctx, EVP_sha256(), nullptr, parsed_key) <= 0 || EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0 || EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
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

int verify_with_rsa(const unsigned char *public_rsa_key, const int key_size, const unsigned char *data, const uint64_t data_size, const unsigned char *signature, const unsigned int signature_size) {
	EVP_PKEY *parsed_key = d2i_PUBKEY(nullptr, &public_rsa_key, key_size);
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

	EVP_PKEY_CTX *pkey_ctx = nullptr;
	if (EVP_DigestVerifyInit(ctx, &pkey_ctx, EVP_sha256(), nullptr, parsed_key) <= 0 || EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0 || EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
		fprintf(stderr, "Failed to initialize verification:\n");
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
