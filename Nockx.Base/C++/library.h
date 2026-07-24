#ifndef NOCKX_BASE_CPP_LIBRARY_H
#define NOCKX_BASE_CPP_LIBRARY_H

#include <cstdint>
#include <cstddef>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

struct AsymmetricKey;
struct AesKey;

extern "C" {
	EXPORT void destroy_asymmetric_key(const AsymmetricKey *asymmetric_key);

	EXPORT void init_secure_heap();

	EXPORT void free_pointer(void *ptr);

	EXPORT void free_openssl_pointer(void *ptr);

	EXPORT unsigned char generate_key(const char *key_type);

	EXPORT AsymmetricKey *read_key_from_file(const char *file_name, const char *key_type);

	EXPORT unsigned char *extract_public_key(const AsymmetricKey *private_key, int *public_key_size);

	EXPORT unsigned char *read_public_key_from_string(const char *input, const char *key_type, int *public_key_size);

	EXPORT unsigned char *encrypt_aes_key_with_ml_kem(const unsigned char *public_kem_key, unsigned int kem_key_size, const AesKey *aes_key, unsigned int *wrapped_encrypted_aes_key_length);

	EXPORT AesKey *decrypt_aes_key_with_ml_kem(const AsymmetricKey *private_kem_key, const unsigned char *ciphertext,  unsigned int ciphertext_length);

	EXPORT unsigned char get_signature_size(const AsymmetricKey *private_key, const unsigned char *data, uint64_t data_size, uint64_t *signature_size);

	EXPORT unsigned char sign_with_ml_dsa(const AsymmetricKey *private_key, const unsigned char *data, uint64_t data_size, unsigned char *signature, uint64_t *signature_size);

	EXPORT int verify_with_ml_dsa(const unsigned char *public_key, int key_size, const unsigned char *data, uint64_t data_size, const unsigned char *signature, unsigned int signature_size);
}

#endif // NOCKX_BASE_CPP_LIBRARY_H