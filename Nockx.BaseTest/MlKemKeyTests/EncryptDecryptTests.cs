using System.Text;
using Nockx.Base.CryptographyTypes.MlKem;

namespace Nockx.BaseTest.MlKemKeyTests;

public class EncryptDecryptTests {
	[Fact]
	public void EncryptDecryptSuccess() {
		const string input = "Hello";
		
		using MlKemKey mlKemKey = MlKemKey.ReadKeyFromFile("mlkemtestkey.pem");
		byte[] decryptedBytes = mlKemKey.DecryptAesKey(mlKemKey.EncryptRsaEncryptedAesKey(Encoding.UTF8.GetBytes(input)));
		Assert.Equal(input, Encoding.UTF8.GetString(decryptedBytes));
	}
	
	[Fact]
	public void EncryptDecryptWrongKeyFail() {
		using MlKemKey mlKemKey = MlKemKey.ReadKeyFromFile("mlkemtestkey.pem");

		byte[] encryptedBytes = mlKemKey.EncryptRsaEncryptedAesKey([.."Hello"u8]);
		using MlKemKey mlKemKey2 = MlKemKey.ReadKeyFromFile("mlkemtestkey2.pem");
		Assert.Throws<InvalidOperationException>(() => mlKemKey2.DecryptAesKey(encryptedBytes));
	}
}