#ifndef NOCKX_BASE_DSA_CRYPTO_H
#define NOCKX_BASE_DSA_CRYPTO_H

#include "library.h"

extern "C" {
	EXPORT unsigned char *sign_with_ml_dsa(const AsymmetricKey *private_key, const unsigned char *data, uint64_t data_size, uint64_t *signature_size);

	EXPORT int verify_with_ml_dsa(const unsigned char *public_key, int key_size, const unsigned char *data, uint64_t data_size, const unsigned char *signature, unsigned int signature_size);
}

#endif //NOCKX_BASE_DSA_CRYPTO_H
