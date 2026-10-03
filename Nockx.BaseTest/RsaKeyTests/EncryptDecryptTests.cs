using System.Text;
using Nockx.Base.CryptographyTypes.Aes;
using Nockx.Base.CryptographyTypes.Rsa;

namespace Nockx.BaseTest.RsaKeyTests;

public class EncryptDecryptTests {
	[Fact]
	public void EncryptDecryptSuccess() {
		const string input = "Hello";
		
		RsaKey rsaKey = RsaKey.ReadKeyFromFile("rsatestkey.pem");
		AesKey aesKey = AesKey.Generate();
		byte[] encryptedBytes = aesKey.Encrypt(Encoding.UTF8.GetBytes(input));
		AesKey decryptedAesKey = rsaKey.DecryptAesKey(rsaKey.EncryptAesKey(aesKey));
		Assert.Equal(input, Encoding.UTF8.GetString(decryptedAesKey.Decrypt(encryptedBytes)));
	}
	
	[Fact]
	public void EncryptDecryptWrongKeyFail() {
		RsaKey rsaKey = RsaKey.ReadKeyFromFile("rsatestkey.pem");
		AesKey aesKey = AesKey.Generate();

		byte[] encryptedAesKey = rsaKey.EncryptAesKey(aesKey);
		rsaKey = RsaKey.ReadKeyFromFile("rsatestkey2.pem");
		Assert.Throws<InvalidOperationException>(() => rsaKey.DecryptAesKey(encryptedAesKey));
	}
}