using System.Text;
using Nockx.Base.CryptographyTypes.Aes;
using Nockx.Base.CryptographyTypes.Rsa;

namespace Nockx.BaseTest.RsaKeyTests;

public class EncryptDecryptTests {
	[Fact]
	public void EncryptDecryptSuccess() {
		const string input = "Hello";
		
		using RsaKey rsaKey = RsaKey.ReadKeyFromFile("rsatestkey.pem");
		using AesKey aesKey = AesKey.Generate();
		byte[] encryptedBytes = aesKey.Encrypt(Encoding.UTF8.GetBytes(input));
		using AesKey decryptedAesKey = rsaKey.DecryptAesKey(rsaKey.EncryptAesKey(aesKey));
		Assert.Equal(input, Encoding.UTF8.GetString(decryptedAesKey.Decrypt(encryptedBytes)));
	}
	
	[Fact]
	public void EncryptDecryptWrongKeyFail() {
		using RsaKey rsaKey = RsaKey.ReadKeyFromFile("rsatestkey.pem");
		using AesKey aesKey = AesKey.Generate();

		byte[] encryptedAesKey = rsaKey.EncryptAesKey(aesKey);
		using RsaKey rsaKey2 = RsaKey.ReadKeyFromFile("rsatestkey2.pem");
		Assert.Throws<InvalidOperationException>(() => rsaKey2.DecryptAesKey(encryptedAesKey));
	}
}