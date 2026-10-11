using System.Runtime.InteropServices;

namespace Nockx.Base.CryptographyTypes.MlKem;

internal static partial class MlKemCryptography {
	// These names are a bit confusing, since a plain AES key never touches ML-KEM and any byte array can be encrypted and decrypted with these functions, but the architecture is to just use RSA-encrypted AES keys
	[LibraryImport("libnockx-base")]
	internal static unsafe partial IntPtr encrypt_aes_key_with_ml_kem([In] byte[] publicKemKey, uint kemKeySize, [In] byte[] rsaEncryptedAesKey, uint rsaEncryptedAesKeyLength, uint *wrappedEncryptedAesKeyLength);
	
	// This should return a SafeHandle if it were to actually return a plain AES key, but the returned data is still RSA-encrypted, so no need
	[LibraryImport("libnockx-base")]
	internal static unsafe partial IntPtr decrypt_aes_key_with_ml_kem(AsymmetricKey privateKemKey, [In] byte[] ciphertext, uint ciphertextLength, uint *plaintextLength);
}