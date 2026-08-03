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
	
	public static void InitSecureHeap() => Init.init_secure_heap();
	
	public static string Md5Hash(string input) => MD5.HashData(Encoding.Default.GetBytes(input)).Aggregate(new StringBuilder(), (sb, cur) => sb.Append(cur.ToString("x2"))).ToString();
}