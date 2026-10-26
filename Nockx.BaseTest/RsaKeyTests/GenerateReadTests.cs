using Nockx.Base;
using Nockx.Base.CryptographyTypes.Rsa;

namespace Nockx.BaseTest.RsaKeyTests;

public class GenerateReadTests {
	[Fact]
	public void ReadSuccess() {
		using RsaKey key = RsaKey.ReadKeyFromFile("rsatestkey.pem");
		Assert.False(key.IsInvalid);
	}

	[Fact]
	public void ReadWrongTypeFail() => Assert.Throws<InvalidOperationException>(() => RsaKey.ReadKeyFromFile("mlkemtestkey.pem"));
	
	[Fact]
	public void ReadInvalidKeyFail() => Assert.Throws<InvalidOperationException>(() => RsaKey.ReadKeyFromFile("invalidtestkey.pem"));
	
	[Fact]
	public void ReadFileNotFoundFail() => Assert.Throws<FileNotFoundException>(() => RsaKey.ReadKeyFromFile("nonexistentkey.pem"));

	[Fact]
	public void GenerateReadSuccess() {
		string fileName = $"{Cryptography.Rsa.ToLower()}_private_key.pem";
		
		try {
			RsaKey.GenerateKeyFile();
			using RsaKey key = RsaKey.ReadKeyFromFile(fileName);
			Assert.False(key.IsInvalid);
		} finally {
			if (File.Exists(fileName))
				File.Delete(fileName);
		}
	}
}