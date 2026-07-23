using System.Runtime.InteropServices;
using Nockx.Base.CryptographyTypes.Rsa;

namespace Nockx.Base;

internal static partial class HelperFunctions {
	[LibraryImport("libnockx-base")]
	internal static partial void destroy_asymmetric_key(IntPtr asymmetricKey);
	
	[LibraryImport("libnockx-base")]
	internal static unsafe partial IntPtr extract_public_key(IntPtr asymmetricKey, int *publicKeySize);

	[LibraryImport("libnockx-base")]
	internal static unsafe partial void free_pointer(void *ptr);
	
	[LibraryImport("libnockx-base")]
	internal static partial byte generate_key([MarshalAs(UnmanagedType.LPStr)] string keyType);
	
	[LibraryImport("libnockx-base")]
	internal static partial RsaKey read_key_from_file([MarshalAs(UnmanagedType.LPStr)] string fileName, [MarshalAs(UnmanagedType.LPStr)] string keyType);
}