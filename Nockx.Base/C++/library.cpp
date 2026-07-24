#include "library.h"

#include "aes_crypto.h"
#include "secure_key.h"

#include <string>
#include <vector>
#include <algorithm>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/decoder.h>

#define WRAPPED_KEY_LEN 60

struct AsymmetricKey {
	SecureKey key;
	std::string type;

	// This constructor should always be called with a try/catch statement because key(der_len) could throw an exception, which could otherwise cause a segfault downstream
	AsymmetricKey(const std::string &key_type, const uint8_t *der_bytes, const int der_len) : key(der_len) {
		memcpy(key.data, der_bytes, der_len);
		type = key_type;
	}
};

void destroy_asymmetric_key(const AsymmetricKey *asymmetric_key) {
	delete asymmetric_key;
}

void init_secure_heap() {
	if (CRYPTO_secure_malloc_init(65536, 16) != 1)
		throw std::runtime_error("CRYPTO_secure_malloc_init failed");
}

void free_pointer(void *ptr) {
	free(ptr);
}

void free_openssl_pointer(void *ptr) {
	OPENSSL_free(ptr);
}

unsigned char generate_key(const char *key_type) {
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	std::string key_type_str(key_type);
	EVP_PKEY *key = key_type_str != "RSA" ? EVP_PKEY_Q_keygen(nullptr, nullptr, key_type) : EVP_PKEY_Q_keygen(nullptr, nullptr, key_type, 2048);

	if (!key) {
		fprintf(stderr, "Error generating key:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	std::ranges::transform(key_type_str, key_type_str.begin(), tolower);
	FILE *file = fopen((key_type_str + std::string("_private_key.pem")).c_str(), "w");
	if (!file) {
		perror("fopen");
		return 0;
	}

	if (!PEM_write_PrivateKey(file, key, nullptr, nullptr, 0, nullptr, nullptr)) {
		fprintf(stderr, "Error writing private key:\n");
		ERR_print_errors_fp(stderr);
		fclose(file);
		return 0;
	}

	fclose(file);
	EVP_PKEY_free(key);

	return 1;
}

AsymmetricKey *read_key_from_file(const char *file_name, const char *key_type) {
	BIO *bio = BIO_new_file(file_name, "r");
	if (!bio) {
		fprintf(stderr, "Error opening private key file:\n");
		ERR_print_errors_fp(stderr);
		return nullptr;
	}

	EVP_PKEY *key = nullptr;
	EVP_PKEY *candidate = nullptr;
	while ((candidate = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr)) != nullptr) {
		if (strcmp(EVP_PKEY_get0_type_name(candidate), key_type) == 0) {
			key = candidate;
			break;
		}
		EVP_PKEY_free(candidate);
	}

	BIO_free(bio);

	if (!key) {
		fprintf(stderr, "Error reading key:\n");
		ERR_print_errors_fp(stderr);
		return nullptr;
	}

	uint8_t *der_bytes = nullptr;
	int der_len = i2d_PrivateKey(key, &der_bytes);
	EVP_PKEY_free(key);
	if (der_len <= 0) {
		fprintf(stderr, "Error converting private key to DER:\n");
		ERR_print_errors_fp(stderr);
		return nullptr;
	}

	AsymmetricKey *asymmetric_key;
	try {
		asymmetric_key = new AsymmetricKey(key_type, der_bytes, der_len);
	} catch (...) {
		asymmetric_key = nullptr;
	}

	OPENSSL_clear_free(der_bytes, der_len);
	return asymmetric_key;
}

unsigned char *extract_public_key(const AsymmetricKey *private_key, int *public_key_size) {
	if (!private_key) {
		fprintf(stderr, "Key is null\n");
		return nullptr;
	}

	int nid = OBJ_txt2nid(private_key->type.c_str());
	if (nid == NID_undef) {
		fprintf(stderr, "Unrecognized key type: %s\n", private_key->type.c_str());
		return nullptr;
	}

	const uint8_t *private_key_pointer = private_key->key.data;
	EVP_PKEY *pkey = d2i_PrivateKey(nid, nullptr, &private_key_pointer, private_key->key.len);
	if (!pkey) {
		fprintf(stderr, "Error reconstructing private key:\n");
		ERR_print_errors_fp(stderr);
		return nullptr;
	}

	uint8_t *public_key = nullptr;
	*public_key_size = i2d_PUBKEY(pkey, &public_key);
	if (*public_key_size <= 0) {
		EVP_PKEY_free(pkey);
		fprintf(stderr, "Error extracting public key:\n");
		ERR_print_errors_fp(stderr);
		return nullptr;
	}

	EVP_PKEY_free(pkey);

	return public_key;
}

unsigned char *read_public_key_from_string(const char *input, const char *key_type, int *public_key_size) {
	BIO *bio = BIO_new_mem_buf(input, static_cast<int>(strlen(input)));
	if (!bio) {
		fprintf(stderr, "Error creating buffer for public key string:\n");
		ERR_print_errors_fp(stderr);
		return nullptr;
	}

	EVP_PKEY *key = nullptr;
	EVP_PKEY *candidate = nullptr;
	while ((candidate = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr)) != nullptr) {
		if (strcmp(EVP_PKEY_get0_type_name(candidate), key_type) == 0) {
			key = candidate;
			break;
		}
		EVP_PKEY_free(candidate);
	}

	if (!key) {
		fprintf(stderr, "Error reading key:\n");
		ERR_print_errors_fp(stderr);
		return nullptr;
	}

	unsigned char *public_key = nullptr;
	*public_key_size = i2d_PUBKEY(key, &public_key);
	EVP_PKEY_free(key);
	BIO_free(bio);

	return public_key;
}

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

	if (ciphertext == nullptr) {
		fprintf(stderr, "Error allocating ciphertext:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	auto shared_secret = static_cast<unsigned char *>(OPENSSL_secure_malloc(ss_length));

	if (shared_secret == nullptr) {
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

	/*
	 * Allocate WRAPPED_KEY_LEN + cipher text length for the result,
	 * as the wrapped key will be stored in it by the next function call
	 * and the ciphertext created by EVP_PKEY_encapsulate will be appended to it.
	 * The ciphertext can be decrypted using the private ML-KEM key,
	 * after which you will retrieve a shared secret, which can be used to unwrap the AES key.
	 */
	*wrapped_encrypted_aes_key_length = WRAPPED_KEY_LEN + ct_length;
	auto wrapped_encrypted_aes_key = static_cast<unsigned char *>(OPENSSL_malloc(*wrapped_encrypted_aes_key_length));
	if (wrapped_encrypted_aes_key == nullptr) {
		fprintf(stderr, "Error allocating wrapped_encrypted_aes_key:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		OPENSSL_free(ciphertext);
		OPENSSL_secure_clear_free(shared_secret, ss_length);
		return nullptr;
	}

	if (!wrap_aes_key_with_aes_gcm(aes_key, shared_secret, wrapped_encrypted_aes_key)) {
		fprintf(stderr, "Wrapping AES key with ML-KEM failed\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		OPENSSL_free(ciphertext);
		OPENSSL_secure_clear_free(shared_secret, ss_length);
		OPENSSL_free(wrapped_encrypted_aes_key);
		return nullptr;
	}

	memcpy(wrapped_encrypted_aes_key + WRAPPED_KEY_LEN, ciphertext, ct_length);

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(parsed_key);
	OPENSSL_free(ciphertext);
	OPENSSL_secure_clear_free(shared_secret, ss_length);

	return wrapped_encrypted_aes_key;
}

AesKey *decrypt_aes_key_with_ml_kem(const AsymmetricKey *private_kem_key, const unsigned char *ciphertext, const unsigned int ciphertext_length) {
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

	std::vector<uint8_t> shared_secret(ss_length);
	if (EVP_PKEY_decapsulate(ctx, shared_secret.data(), &ss_length, true_ciphertext.data(), true_ciphertext.size()) <= 0) {
		fprintf(stderr, "Failed to decapsulate:\n");
		ERR_print_errors_fp(stderr);
		OPENSSL_cleanse(shared_secret.data(), shared_secret.size());
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return nullptr;
	}

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(parsed_key);

	AesKey *unwrapped_key = unwrap_aes_key_with_aes_gcm(ciphertext, shared_secret.data());
	OPENSSL_cleanse(shared_secret.data(), shared_secret.size());

	if (!unwrapped_key)
		fprintf(stderr, "Failed to unwrap AES key\n");

	return unwrapped_key;
}

unsigned char get_signature_size(const AsymmetricKey *private_key, const unsigned char *data, const uint64_t data_size, uint64_t *signature_size) {
	const char *REQUIRED_KEY_TYPE = "ML-DSA-65";

	if (private_key->type != REQUIRED_KEY_TYPE) {
		fprintf(stderr, "Key has to be of type %s, but is of type %s\n", REQUIRED_KEY_TYPE, private_key->type.c_str());
		return 0;
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
		return 0;
	}

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Failed to create context:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_free(parsed_key);
		return 0;
	}

	if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, parsed_key) <= 0) {
		fprintf(stderr, "Failed to initialize signing:\n");
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return 0;
	}

	size_t sig_size;
	if (EVP_DigestSign(ctx, nullptr, &sig_size, data, data_size) <= 0) {
		fprintf(stderr, "Failed to sign (size check):\n");
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return 0;
	}

	*signature_size = sig_size;

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(parsed_key);

	return 1;
}

unsigned char sign_with_ml_dsa(const AsymmetricKey *private_key, const unsigned char *data, const uint64_t data_size, unsigned char *signature, uint64_t *signature_size) {
	const char *REQUIRED_KEY_TYPE = "ML-DSA-65";

	if (private_key->type != REQUIRED_KEY_TYPE) {
		fprintf(stderr, "Key has to be of type %s, but is of type %s\n", REQUIRED_KEY_TYPE, private_key->type.c_str());
		return 0;
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
		return 0;
	}

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Failed to create context:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_free(parsed_key);
		return 0;
	}

	if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, parsed_key) <= 0) {
		fprintf(stderr, "Failed to initialize signing:\n");
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return 0;
	}

	size_t sig_size = *signature_size;
	if (EVP_DigestSign(ctx, signature, &sig_size, data, data_size) <= 0) {
		fprintf(stderr, "Failed to sign:\n");
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return 0;
	}

	*signature_size = sig_size;

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(parsed_key);

	return 1;
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

	return result;
}