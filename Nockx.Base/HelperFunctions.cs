using System.Runtime.InteropServices;
using Nockx.Base.CryptographyTypes;
using Nockx.Base.CryptographyTypes.MlDsa;
using Nockx.Base.CryptographyTypes.MlKem;
using Nockx.Base.CryptographyTypes.Rsa;

namespace Nockx.Base;

internal static partial class HelperFunctions {
	[LibraryImport("libnockx-base")]
	internal static partial void destroy_asymmetric_key(IntPtr asymmetricKey);
	
	[LibraryImport("libnockx-base")]
	internal static unsafe partial IntPtr extract_public_key(AsymmetricKey asymmetricKey, int *publicKeySize);

	[LibraryImport("libnockx-base")]
	internal static unsafe partial void free_pointer(void *ptr);

	[LibraryImport("libnockx-base")]
	internal static unsafe partial void free_openssl_pointer(void *ptr);
	
	[LibraryImport("libnockx-base")]
	internal static partial byte generate_key([MarshalAs(UnmanagedType.LPStr)] string keyType);
	
	[LibraryImport("libnockx-base", EntryPoint = "read_key_from_file")]
	internal static partial RsaKey ReadRsaKeyFromFile([MarshalAs(UnmanagedType.LPStr)] string fileName, [MarshalAs(UnmanagedType.LPStr)] string keyType = RsaKey.KeyType);
	
	[LibraryImport("libnockx-base", EntryPoint = "read_key_from_file")]
	internal static partial MlKemKey ReadMlKemKeyFromFile([MarshalAs(UnmanagedType.LPStr)] string fileName, [MarshalAs(UnmanagedType.LPStr)] string keyType = MlKemKey.KeyType);
	
	[LibraryImport("libnockx-base", EntryPoint = "read_key_from_file")]
	internal static partial MlDsaKey ReadMlDsaKeyFromFile([MarshalAs(UnmanagedType.LPStr)] string fileName, [MarshalAs(UnmanagedType.LPStr)] string keyType = MlDsaKey.KeyType);
}