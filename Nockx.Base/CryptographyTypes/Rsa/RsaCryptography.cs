using System.Runtime.InteropServices;
using Nockx.Base.CryptographyTypes.Aes;

namespace Nockx.Base.CryptographyTypes.Rsa;

internal static partial class RsaCryptography {
	[LibraryImport("libnockx-base")]
	internal static unsafe partial IntPtr encrypt_aes_key_with_rsa([In] byte[] publicRsaKey, uint keySize, AesKey aesKey, uint *ciphertextLength);

	[LibraryImport("libnockx-base")]
	internal static unsafe partial AesKey decrypt_aes_key_with_rsa(RsaKey privateRsaKey, [In] byte[] ciphertext, uint ciphertextLength);

	[LibraryImport("libnockx-base")]
	internal static unsafe partial IntPtr sign_with_rsa(RsaKey privateRsaKey, [In] byte[] data, ulong dataSize, ulong *signatureSize);

	[LibraryImport("libnockx-base")]
	internal static unsafe partial int verify_with_rsa([In] byte[] publicRsaKey, int keySize, [In] byte[] data, ulong dataSize, [In] byte[] signature, uint signatureSize);
}