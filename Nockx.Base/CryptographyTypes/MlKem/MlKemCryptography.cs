using System.Runtime.InteropServices;

namespace Nockx.Base.CryptographyTypes.MlKem;

internal static partial class MlKemCryptography {
	[LibraryImport("libnockx-base")]
	internal static unsafe partial IntPtr encrypt_aes_key_with_ml_kem([In] byte[] publicKemKey, uint kemKeySize, [In] byte[] rsaEncryptedAesKey, uint rsaEncryptedAesKeyLength, uint *wrappedEncryptedAesKeyLength);
	
	// TODO: this might be an unsafe IntPtr return and should then be changed to some SafeHandle
	[LibraryImport("libnockx-base")]
	internal static unsafe partial IntPtr decrypt_aes_key_with_ml_kem(AsymmetricKey privateKemKey, [In] byte[] ciphertext, uint ciphertextLength, uint *plaintextLength);
}