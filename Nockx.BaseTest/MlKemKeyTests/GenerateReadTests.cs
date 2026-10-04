using Nockx.Base;
using Nockx.Base.CryptographyTypes.MlKem;

namespace Nockx.BaseTest.MlKemKeyTests;

public class GenerateReadTests {
	[Fact]
	public void ReadSuccess() => Assert.False(MlKemKey.ReadKeyFromFile("mlkemtestkey.pem").IsInvalid);
	
	[Fact]
	public void ReadWrongTypeFail() => Assert.Throws<InvalidOperationException>(() => MlKemKey.ReadKeyFromFile("rsatestkey.pem"));
	
	[Fact]
	public void ReadInvalidKeyFail() => Assert.Throws<InvalidOperationException>(() => MlKemKey.ReadKeyFromFile("invalidtestkey.pem"));
	
	[Fact]
	public void ReadFileNotFoundFail() => Assert.Throws<FileNotFoundException>(() => MlKemKey.ReadKeyFromFile("nonexistentkey.pem"));

	[Fact]
	public void GenerateReadSuccess() {
		MlKemKey.GenerateKeyFile();
		Assert.False(MlKemKey.ReadKeyFromFile($"{Cryptography.MlKem768.ToLower()}_private_key.pem").IsInvalid);
		
		File.Delete($"{Cryptography.MlKem768.ToLower()}_private_key.pem");
	}
}