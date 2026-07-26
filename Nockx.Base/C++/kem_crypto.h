#ifndef NOCKX_BASE_KEM_CRYPTO_H
#define NOCKX_BASE_KEM_CRYPTO_H

#include "library.h"

extern "C" {
	EXPORT unsigned char *encrypt_aes_key_with_ml_kem(const unsigned char *public_kem_key, unsigned int kem_key_size, const AesKey *aes_key, unsigned int *wrapped_encrypted_aes_key_length);

	EXPORT AesKey *decrypt_aes_key_with_ml_kem(const AsymmetricKey *private_kem_key, const unsigned char *ciphertext, unsigned int ciphertext_length);
}

#endif //NOCKX_BASE_KEM_CRYPTO_H
