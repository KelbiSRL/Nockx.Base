using System.Text;
using Nockx.Base.CryptographyTypes;
using Nockx.Base.CryptographyTypes.Aes;

namespace Nockx.BaseTest.NockxKeyTests;

public class EncryptDecryptKeyTests {
	[Fact]
	public void EncryptDecryptSuccess() {
		const string input = "Hello";
		
		using NockxKey nockxKey = NockxKey.ReadKeyFromFile("nockxtestkey.pem");
		using AesKey aesKey = AesKey.Generate();
		using AesKey aesKey2 = nockxKey.DecryptAesKey(nockxKey.EncryptAesKey(aesKey));

		Assert.Equal(input, Encoding.UTF8.GetString(aesKey2.Decrypt(aesKey.Encrypt(Encoding.UTF8.GetBytes(input)))));
	}
	
	[Fact]
	public void EncryptDecryptWrongKeyFail() {
		using AesKey aesKey = AesKey.Generate();
		using NockxKey nockxKey = NockxKey.ReadKeyFromFile("nockxtestkey.pem");
		using NockxKey nockxKey2 = NockxKey.ReadKeyFromFile("nockxtestkey2.pem");
		byte[] encryptedData = nockxKey.EncryptAesKey(aesKey);
		Assert.Throws<InvalidOperationException>(() => nockxKey2.DecryptAesKey(encryptedData));
	}
	
	[Fact]
	public void EncryptDecryptWrongRsaKeyFail() {
		using AesKey aesKey = AesKey.Generate();
		using NockxKey nockxKey = NockxKey.ReadKeyFromFile("nockxtestkey.pem");
		using NockxKey nockxKey2 = NockxKey.ReadKeyFromFile("nockxwrongrsatestkey.pem");
		byte[] encryptedData = nockxKey.EncryptAesKey(aesKey);
		Assert.Throws<InvalidOperationException>(() => nockxKey2.DecryptAesKey(encryptedData));
	}
	
	[Fact]
	public void EncryptDecryptWrongMlKemKeyFail() {
		using AesKey aesKey = AesKey.Generate();
		using NockxKey nockxKey = NockxKey.ReadKeyFromFile("nockxtestkey.pem");
		using NockxKey nockxKey2 = NockxKey.ReadKeyFromFile("nockxwrongmlkemtestkey.pem");
		byte[] encryptedData = nockxKey.EncryptAesKey(aesKey);
		Assert.Throws<InvalidOperationException>(() => nockxKey2.DecryptAesKey(encryptedData));
	}
}