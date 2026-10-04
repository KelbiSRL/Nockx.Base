using System.Text;
using Nockx.Base.CryptographyTypes.MlKem;

namespace Nockx.BaseTest.MlKemKeyTests;

public class EncryptDecryptTests {
	[Fact]
	public void EncryptDecryptSuccess() {
		const string input = "Hello";
		
		MlKemKey mlKemKey = MlKemKey.ReadKeyFromFile("mlkemtestkey.pem");
		byte[] decryptedBytes = mlKemKey.DecryptAesKey(mlKemKey.EncryptRsaEncryptedAesKey(Encoding.UTF8.GetBytes(input)));
		Assert.Equal(input, Encoding.UTF8.GetString(decryptedBytes));
	}
	
	[Fact]
	public void EncryptDecryptWrongKeyFail() {
		MlKemKey mlKemKey = MlKemKey.ReadKeyFromFile("mlkemtestkey.pem");

		byte[] encryptedBytes = mlKemKey.EncryptRsaEncryptedAesKey([.."Hello"u8]);
		mlKemKey = MlKemKey.ReadKeyFromFile("mlkemtestkey2.pem");
		Assert.Throws<InvalidOperationException>(() => mlKemKey.DecryptAesKey(encryptedBytes));
	}
}