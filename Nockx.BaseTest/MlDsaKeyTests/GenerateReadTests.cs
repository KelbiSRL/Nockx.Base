using Nockx.Base;
using Nockx.Base.CryptographyTypes.MlDsa;

namespace Nockx.BaseTest.MlDsaKeyTests;

public class GenerateReadTests {
	[Fact]
	public void ReadSuccess() {
		using MlDsaKey key = MlDsaKey.ReadKeyFromFile("mldsatestkey.pem");
		Assert.False(key.IsInvalid);
	}

	[Fact]
	public void ReadWrongTypeFail() => Assert.Throws<InvalidOperationException>(() => MlDsaKey.ReadKeyFromFile("rsatestkey.pem"));

	[Fact]
	public void ReadInvalidKeyFail() => Assert.Throws<InvalidOperationException>(() => MlDsaKey.ReadKeyFromFile("invalidtestkey.pem"));

	[Fact]
	public void ReadFileNotFoundFail() => Assert.Throws<FileNotFoundException>(() => MlDsaKey.ReadKeyFromFile("nonexistentkey.pem"));

	[Fact]
	public void GenerateReadSuccess() {
		string fileName = $"{Cryptography.MlDsa65.ToLower()}_private_key.pem";
		
		try {
			MlDsaKey.GenerateKeyFile();
			using MlDsaKey key = MlDsaKey.ReadKeyFromFile(fileName);
			Assert.False(key.IsInvalid);
		} finally {
			if (File.Exists(fileName))
				File.Delete(fileName);
		}
	}
}