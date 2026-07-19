#ifndef NOCKX_BASE_SECURE_KEY_H
#define NOCKX_BASE_SECURE_KEY_H

#include <stdexcept>
#include <openssl/crypto.h>

struct SecureKey {
	uint8_t *data;
	int len;

	SecureKey(const int n) : len(n) {
		data = static_cast<uint8_t *>(CRYPTO_secure_malloc(n, __FILE__, __LINE__));
		if (data == nullptr)
			throw std::runtime_error("Key generation failed");
	}

	~SecureKey() {
		CRYPTO_secure_clear_free(data, len, __FILE__, __LINE__);
	}

	SecureKey(const SecureKey &) = delete;
	SecureKey & operator=(const SecureKey &) = delete;

	SecureKey(SecureKey &&other) noexcept : data(other.data), len(other.len) {
		other.data = nullptr;
		other.len = 0;
	}

	SecureKey & operator=(SecureKey &&other) noexcept {
		if (this != &other) {
			CRYPTO_secure_clear_free(data, len, __FILE__, __LINE__);
			data = other.data;
			len = other.len;
			other.data = nullptr;
			other.len = 0;
		}

		return *this;
	}
};

#endif //NOCKX_BASE_SECURE_KEY_H
