#ifndef NOCKX_BASE_CPP_LIBRARY_H
#define NOCKX_BASE_CPP_LIBRARY_H

#include "asymmetric_key.h"

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

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
}

#endif // NOCKX_BASE_CPP_LIBRARY_H