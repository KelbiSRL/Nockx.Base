using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Nockx.Base.CryptographyTypes.MlDsa;
using Nockx.Base.CryptographyTypes.MlKem;
using Nockx.Base.CryptographyTypes.Rsa;

namespace Nockx.Base;

public static class Cryptography {
	public const string MlKem768 = MlKemKey.KeyType;
	public const string MlDsa65 = MlDsaKey.KeyType;
	public const string Rsa = RsaKey.KeyType;
	
	public static void InitSecureHeap(ulong size = 1 << 20, ulong minSize = 16) => Init.init_secure_heap(size, minSize);
	
	public static string Md5Hash(string input) => MD5.HashData(Encoding.Default.GetBytes(input)).Aggregate(new StringBuilder(), (sb, cur) => sb.Append(cur.ToString("x2"))).ToString();

	public static unsafe string GetKeyType(byte[] publicKey) {
		IntPtr keyTypePointer = HelperFunctions.get_key_type(publicKey, (uint) publicKey.Length);
		if (keyTypePointer == IntPtr.Zero)
			throw new InvalidOperationException("Key type could not be extracted from public key");

		try {
			return Marshal.PtrToStringUTF8(keyTypePointer)!;
		} finally {
			HelperFunctions.free_pointer((void *) keyTypePointer);
		}
	}
}