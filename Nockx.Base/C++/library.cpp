// TODO: disable core dumping as much as possible (Linux: RLIMIT_CORE and MADV_DONTDUMP (may not stop it fully on android. /data/tombstones has to be checked to see if it still gets dumped), MacOS: also RLIMIT_CORE, but crashreporterd would have to be disabled as well by the user, Windows: probably with WerAddExcludedApplication and SetUnhandledExceptionFilter). Core dumping can lead keys to be stored to the drive.

#include "library.h"

#include "secure_key.h"

#include <string>
#include <vector>
#include <algorithm>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>

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
