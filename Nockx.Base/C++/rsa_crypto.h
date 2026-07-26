#ifndef NOCKX_BASE_RSA_CRYPTO_H
#define NOCKX_BASE_RSA_CRYPTO_H

#include "library.h"

extern "C" {
	EXPORT unsigned char *encrypt_aes_key_with_rsa(const unsigned char *public_rsa_key, unsigned int key_size, const AesKey *aes_key, unsigned int *ciphertext_length);

	EXPORT AesKey *decrypt_aes_key_with_rsa(const AsymmetricKey *private_rsa_key, const unsigned char *ciphertext, unsigned int ciphertext_length);

	EXPORT unsigned char *sign_with_rsa(const AsymmetricKey *private_rsa_key, const unsigned char *data, uint64_t data_size, uint64_t *signature_size);

	EXPORT int verify_with_rsa(const unsigned char *public_rsa_key, int key_size, const unsigned char *data, uint64_t data_size, const unsigned char *signature, unsigned int signature_size);
}

#endif //NOCKX_BASE_RSA_CRYPTO_H
