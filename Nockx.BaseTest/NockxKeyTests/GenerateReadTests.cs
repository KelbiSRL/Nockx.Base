using Nockx.Base.CryptographyTypes;

namespace Nockx.BaseTest.NockxKeyTests;

public class GenerateReadTests {
	[Fact]
	public void ReadSuccess() => Assert.False(NockxKey.ReadKeyFromFile("nockxtestkey.pem").IsInvalid);
	
	[Fact]
	public void ReadInvalidKeyFail() => Assert.Throws<InvalidOperationException>(() => NockxKey.ReadKeyFromFile("invalidtestkey.pem"));
	
	[Fact]
	public void ReadFileNotFoundFail() => Assert.Throws<FileNotFoundException>(() => NockxKey.ReadKeyFromFile("nonexistentkey.pem"));

	[Fact]
	public void GenerateReadSuccess() {
		NockxKey.GenerateCombinedKeyFile();
		Assert.False(NockxKey.ReadKeyFromFile().IsInvalid);
		
		File.Delete("private_key.pem");
	}
}