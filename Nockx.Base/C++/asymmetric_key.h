#ifndef NOCKX_BASE_ASYMMETRIC_KEY_H
#define NOCKX_BASE_ASYMMETRIC_KEY_H

#include "secure_key.h"

#include <string>

struct AsymmetricKey {
	SecureKey key;
	std::string type;

	// This constructor should always be called with a try/catch statement because key(der_len) could throw an exception, which could otherwise cause a segfault downstream
	AsymmetricKey(const std::string &key_type, const uint8_t *der_bytes, const int der_len) : key(der_len) {
		memcpy(key.data, der_bytes, der_len);
		type = key_type;
	}
};

#endif //NOCKX_BASE_ASYMMETRIC_KEY_H
