using System.Runtime.InteropServices;

namespace Nockx.Base.CryptographyTypes.MlDsa;

internal static partial class MlDsaCryptography {
	[LibraryImport("libnockx-base")]
	internal static unsafe partial IntPtr sign_with_ml_dsa(MlDsaKey dsaPrivateKey, [In] byte[] data, ulong dataSize, ulong *signatureSize);

	[LibraryImport("libnockx-base")]
	internal static unsafe partial int verify_with_ml_dsa([In] byte[] dsaPublicKey, int keySize, [In] byte[] data, ulong dataSize, [In] byte[] signature, uint signatureSize);
}