using System.Runtime.InteropServices;

namespace Nockx.Base.CryptographyTypes.Aes;

internal static partial class AesCryptography {
	[LibraryImport("libnockx-base")]
	internal static partial AesKey create_aes_key();

	[LibraryImport("libnockx-base")]
	internal static partial void destroy_aes_key(IntPtr aesKey);

	[LibraryImport("libnockx-base")]
	internal static unsafe partial int generate_iv(byte *iv);

	[LibraryImport("libnockx-base")]
	internal static unsafe partial IntPtr encrypt_with_aes_gcm([In] byte[] plaintext, ulong plaintextLength, AesKey aesKey, [In] byte[] iv, [In] byte[] aad, ulong aadLength, ulong *ciphertextLength);

	[LibraryImport("libnockx-base")]
	internal static unsafe partial IntPtr decrypt_with_aes_gcm([In] byte[] ciphertext, ulong ciphertextLength, AesKey aesKey, [In] byte[] iv, [In] byte[] aad, ulong aadLength, ulong *plaintextLength);
	
	[LibraryImport("libnockx-base")]
	internal static partial AesGcmStreamContext create_gcm_context_for_stream(byte forEncryption, AesKey aesKey, [In] byte[] iv, [In] byte[] aad, ulong aadLength);
	
	[LibraryImport("libnockx-base")]
	internal static unsafe partial int gcm_stream_update(AesGcmStreamContext ctx, byte *input, int inputLength, byte *output);
	
	[LibraryImport("libnockx-base")]
	internal static unsafe partial sbyte gcm_stream_final(AesGcmStreamContext ctx, byte forEncryption, byte *tag);
	
	[LibraryImport("libnockx-base")]
	internal static partial void gcm_stream_dispose(IntPtr ctx);
}