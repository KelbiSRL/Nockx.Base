using System.Runtime.InteropServices;
using System.Text;

namespace Nockx.Base.CryptographyTypes.Rsa;

internal static class RsaCryptography {
	internal const string KeyType = "RSA";
	
	internal static bool GenerateKey() => HelperFunctions.generate_key(KeyType) != 0;
	
	internal static RsaKey ReadKeyFromFile(string fileName) => HelperFunctions.read_key_from_file(fileName, KeyType);
	
	// public static byte[] EncryptAesKey(byte[] aesKey, RsaKeyParameters rsaPublicKey) {
	// 	OaepEncoding rsaEngine = new (new RsaEngine());
	// 	rsaEngine.Init(true, rsaPublicKey);
	// 	return rsaEngine.ProcessBlock(aesKey, 0, aesKey.Length);
	// }
	//
	// public static byte[] DecryptAesKey(byte[] encryptedAesKey, RsaKeyParameters rsaPrivateKey) {
	// 	OaepEncoding rsaEngine = new (new RsaEngine());
	// 	rsaEngine.Init(false, rsaPrivateKey);
	// 	return rsaEngine.ProcessBlock(encryptedAesKey, 0, encryptedAesKey.Length);
	// }
	//
	// public static string Sign(string text, RsaKeyParameters privateKey) {
	// 	byte[] bytes = Encoding.UTF8.GetBytes(text);
	// 	RsaDigestSigner signer = new (new Sha256Digest());
	// 	signer.Init(true, privateKey);
	// 	
	// 	signer.BlockUpdate(bytes, 0, bytes.Length);
	// 	byte[] signature = signer.GenerateSignature();
	//
	// 	return Convert.ToBase64String(signature);
	// }
	//
	// public static bool Verify(string text, string signature, RsaKeyParameters publicKey) {
	// 	byte[] textBytes = Encoding.UTF8.GetBytes(text);
	// 	byte[] signatureBytes = Convert.FromBase64String(signature);
	//
	// 	RsaDigestSigner verifier = new (new Sha256Digest());
	// 	verifier.Init(false, publicKey);
	// 	
	// 	verifier.BlockUpdate(textBytes, 0, textBytes.Length);
	//
	// 	return verifier.VerifySignature(signatureBytes);
	// }
}