using Nockx.Base;
using Nockx.Base.CryptographyTypes.Rsa;

namespace Nockx.BaseTest.RsaKeyTests;

public class GenerateReadTests {
	[Fact]
	public void ReadSuccess() => Assert.False(RsaKey.ReadKeyFromFile("rsatestkey.pem").IsInvalid);
	
	[Fact]
	public void ReadWrongTypeFail() => Assert.Throws<InvalidOperationException>(() => RsaKey.ReadKeyFromFile("mlkemtestkey.pem"));
	
	[Fact]
	public void ReadInvalidKeyFail() => Assert.Throws<InvalidOperationException>(() => RsaKey.ReadKeyFromFile("invalidtestkey.pem"));
	
	[Fact]
	public void ReadFileNotFoundFail() => Assert.Throws<FileNotFoundException>(() => RsaKey.ReadKeyFromFile("nonexistentkey.pem"));

	[Fact]
	public void GenerateReadSuccess() {
		RsaKey.GenerateKeyFile();
		Assert.False(RsaKey.ReadKeyFromFile($"{Cryptography.Rsa.ToLower()}_private_key.pem").IsInvalid);
		
		File.Delete($"{Cryptography.Rsa.ToLower()}_private_key.pem");
	}
}