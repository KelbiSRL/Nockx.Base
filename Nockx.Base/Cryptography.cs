using System.Security.Cryptography;
using System.Text;
using Nockx.Base.CryptographyTypes;
using Nockx.Base.CryptographyTypes.Aes;
using Nockx.Base.CryptographyTypes.MlDsa;
using Nockx.Base.CryptographyTypes.MlKem;
using Nockx.Base.CryptographyTypes.Rsa;
using MlDsaCryptography = Nockx.Base.CryptographyTypes.MlDsa.MlDsaCryptography;
using MlKemCryptography = Nockx.Base.CryptographyTypes.MlKem.MlKemCryptography;

namespace Nockx.Base;

public static class Cryptography {
	public const string MlKem768 = MlKemKey.KeyType;
	public const string MlDsa65 = MlDsaKey.KeyType;
	public const string Rsa = RsaKey.KeyType;
	
	public const int AesKeyLength = 32;
	public const int RsaKeyLength = 256;
	public const int KemEncapsulationLength = 1088;
	
	static Cryptography() {
		Init.InitSecureHeap();
	}
	
	public static void GenerateCombinedKeyFile() {
		// if (File.Exists("private_key.pem"))
		// 	throw new InvalidOperationException("Private key file already exists");
		//
		// if (!GenerateKey(MlKem768) || !GenerateKey(MlDsa65))
		// 	throw new Exception("Key generation failed");
		//
		// RsaKey.GenerateKeyFile();
		//
		// File.AppendAllText("private_key.pem", File.ReadAllText($"{MlKem768.ToLowerInvariant()}_private_key.pem").Trim() + '\n');
		// File.AppendAllText("private_key.pem", File.ReadAllText($"{MlDsa65.ToLowerInvariant()}_private_key.pem").Trim() + '\n');
		// File.AppendAllText("private_key.pem", File.ReadAllText($"{Rsa.ToLowerInvariant()}_private_key.pem"));
		//
		// File.Delete($"{MlKem768.ToLowerInvariant()}_private_key.pem");
		// File.Delete($"{MlDsa65.ToLowerInvariant()}_private_key.pem");
		// File.Delete($"{Rsa.ToLowerInvariant()}_private_key.pem");
	}
	
	// public static bool GenerateKey(string keyType) => MlKemCryptography.GenerateKey(keyType);
	//
	// public static KeyPair ReadKeyFromFile(string fileName, string keyType) => MlKemCryptography.ReadKeyFromFile(fileName, keyType);
	//
	// public static byte[] ReadPublicKeyFromString(string input, string keyType) =>  MlKemCryptography.ReadPublicKeyFromString(input, keyType);
	//
	// public static byte[] EncryptAesKeyWithMlKem(byte[] aesKey, byte[] publicKemKey) => MlKemCryptography.EncryptAesKey(aesKey, publicKemKey);
	//
	// public static byte[] DecryptAesKeyWithMlKem(byte[] ciphertext, byte[] privateKemKey) => MlKemCryptography.DecryptAesKey(ciphertext, privateKemKey);
	//
	// public static byte[] GenerateAesKey() => AesCryptography.GenerateKey();
	//
	// public static byte[] EncryptWithAes(byte[] data, int inputLength, byte[] aesKey) => AesCryptography.Encrypt(data, inputLength, aesKey);
	//
	// public static byte[] DecryptWithAes(byte[] data, byte[] aesKey) => AesCryptography.Decrypt(data, aesKey);
	
	// public static byte[] EncryptAesKeyWithRsa(byte[] aesKey, RsaKeyParameters rsaPublicKey) => RsaCryptography.EncryptAesKey(aesKey, rsaPublicKey);
	//
	// public static byte[] DecryptAesKeyWithRsa(byte[] encryptedAesKey, RsaKeyParameters rsaPrivateKey) => RsaCryptography.DecryptAesKey(encryptedAesKey, rsaPrivateKey);
	//
	// public static string SignWithRsa(string text, RsaKeyParameters privateKey) => RsaCryptography.Sign(text, privateKey);
	//
	// public static bool VerifyWithRsa(string text, string signature, RsaKeyParameters publicKey) => RsaCryptography.Verify(text, signature, publicKey);

	// public static string SignWithMlDsa(string text, byte[] dsaPrivateKey) => Convert.ToBase64String(MlDsaCryptography.Sign(Encoding.UTF8.GetBytes(text), dsaPrivateKey));
	//
	// public static bool VerifyWithMlDsa(string text, string signature, byte[] dsaPublicKey) => MlDsaCryptography.Verify(Encoding.UTF8.GetBytes(text), Convert.FromBase64String(signature), dsaPublicKey);

	public static byte[] EncryptBytes(byte[] input, NockxKey foreignPublicKey, byte[] additionalAuthenticationData, out byte[] iv) {
		AesKey aesKey = AesKey.Generate();
	
		byte[] cipherBytes = aesKey.Encrypt(input, out iv);
		// byte[] encryptedAesKey = EncryptAesKeyWithMlKem(aesKey, foreignKemPublicKey);
		// byte[] doubleEncryptedAesKey = EncryptAesKeyWithRsa(encryptedAesKey[..AesKeyLength], foreignRsaPublicKey);
	
		// byte[] output = new byte[doubleEncryptedAesKey.Length + encryptedAesKey.Length - AesKeyLength + cipherBytes.Length];
		// Buffer.BlockCopy(doubleEncryptedAesKey, 0, output, 0, doubleEncryptedAesKey.Length);
		// Buffer.BlockCopy(encryptedAesKey, AesKeyLength, output, doubleEncryptedAesKey.Length, encryptedAesKey.Length - AesKeyLength);
		// Buffer.BlockCopy(cipherBytes, 0, output, doubleEncryptedAesKey.Length + encryptedAesKey.Length - AesKeyLength, cipherBytes.Length);
		
		// return output;
		return [];
	}
	
	// public static byte[] DecryptBytes(byte[] input, RsaKeyParameters rsaPrivateKey, byte[] kemPrivateKey) {
	// 	byte[] doubleEncryptedAesKey = new byte[RsaKeyLength];
	// 	byte[] encryptedAesKey = new byte[AesKeyLength + KemEncapsulationLength];
	// 	byte[] cipherBytes = new byte[input.Length - doubleEncryptedAesKey.Length - KemEncapsulationLength];
	// 	
	// 	Buffer.BlockCopy(input, 0, doubleEncryptedAesKey, 0, doubleEncryptedAesKey.Length);
	// 	Buffer.BlockCopy(input, doubleEncryptedAesKey.Length, encryptedAesKey, AesKeyLength, KemEncapsulationLength);
	// 	Buffer.BlockCopy(input, doubleEncryptedAesKey.Length + encryptedAesKey.Length - AesKeyLength, cipherBytes, 0, cipherBytes.Length);
	//
	// 	byte[] singleDecryptedAesKey = DecryptAesKeyWithRsa(doubleEncryptedAesKey, rsaPrivateKey);
	// 	Buffer.BlockCopy(singleDecryptedAesKey, 0, encryptedAesKey, 0, AesKeyLength);
	// 	byte[] fullyDecryptedAesKey = DecryptAesKeyWithMlKem(encryptedAesKey, kemPrivateKey);
	// 	byte[] plainBytes = DecryptWithAes(cipherBytes, fullyDecryptedAesKey);
	// 	
	// 	return plainBytes;
	// }
	//
	// public static string Sign(string text, RsaKeyParameters rsaPrivateKey, byte[] dsaPrivateKey) => $"{SignWithRsa(text, rsaPrivateKey)}-{SignWithMlDsa(text, dsaPrivateKey)}";
	//
	// public static bool Verify(string text, string signature, RsaKeyParameters rsaPublicKey, byte[] dsaPublicKey) {
	// 	string[] signatures = signature.Split('-');
	// 	return VerifyWithRsa(text, signatures[0], rsaPublicKey) && VerifyWithMlDsa(text, signatures[1], dsaPublicKey);
	// }
	//
	// public static (RsaKeyParameters, RsaKeyParameters) ImportRsaKey(string file) {
	// 	RsaKeyParameters privateKey;
	// 	using (StreamReader reader = File.OpenText(file)) {
	// 		PemReader pemReader = new (reader);
	// 		privateKey = (RsaKeyParameters) ((AsymmetricCipherKeyPair) pemReader.ReadObject()).Private;
	// 	}
	//
	// 	return (privateKey, new RsaKeyParameters(false, privateKey.Modulus, RsaCryptography.RsaKeyExponent));
	// }
	
	public static string Md5Hash(string input) => MD5.HashData(Encoding.Default.GetBytes(input)).Aggregate(new StringBuilder(), (sb, cur) => sb.Append(cur.ToString("x2"))).ToString();
}