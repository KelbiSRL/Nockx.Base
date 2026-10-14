using Nockx.Base.CryptographyTypes;

namespace Nockx.BaseTest.NockxKeyTests;

public class GenerateReadTests {
	[Fact]
	public void ReadSuccess() {
		using NockxKey nockxKey = NockxKey.ReadKeyFromFile("nockxtestkey.pem");
		Assert.False(nockxKey.IsInvalid);
	}

	[Fact]
	public void ReadInvalidKeyFail() => Assert.Throws<InvalidOperationException>(() => NockxKey.ReadKeyFromFile("invalidtestkey.pem"));
	
	[Fact]
	public void ReadFileNotFoundFail() => Assert.Throws<FileNotFoundException>(() => NockxKey.ReadKeyFromFile("nonexistentkey.pem"));

	[Fact]
	public void GenerateReadSuccess() {
		NockxKey.GenerateCombinedKeyFile();
		using NockxKey nockxKey = NockxKey.ReadKeyFromFile(); 
		Assert.False(nockxKey.IsInvalid);
		
		File.Delete("private_key.pem");
	}
}