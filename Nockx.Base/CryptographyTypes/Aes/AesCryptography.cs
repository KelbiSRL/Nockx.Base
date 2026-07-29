using System.Runtime.InteropServices;

namespace Nockx.Base.CryptographyTypes.Aes;

internal static partial class AesCryptography {
	[LibraryImport("libnockx-base")]
	internal static partial AesKey create_aes_key();

	[LibraryImport("libnockx-base")]
	internal static partial void destroy_aes_key(AesKey aesKey);

	[LibraryImport("libnockx-base")]
	internal static unsafe partial int generate_iv(byte *iv);

	[LibraryImport("libnockx-base")]
	internal static unsafe partial IntPtr encrypt_with_aes_gcm([In] byte[] plaintext, ulong plaintextLength, AesKey aesKey, [In] byte[] iv, [In] byte[] aad, ulong aadLength, ulong *ciphertextLength);

	[LibraryImport("libnockx-base")]
	internal static unsafe partial IntPtr decrypt_with_aes_gcm([In] byte[] ciphertext, ulong ciphertextLength, AesKey aesKey, [In] byte[] iv, [In] byte[] aad, ulong aadLength, ulong *plaintextLength);
}