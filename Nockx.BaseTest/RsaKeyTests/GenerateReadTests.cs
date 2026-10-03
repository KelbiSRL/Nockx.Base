using Nockx.Base;
using Nockx.Base.CryptographyTypes.Rsa;

namespace Nockx.BaseTest.RsaKeyTests;

public class GenerateReadTests {
	[Fact]
	public void GenerateReadSuccess() {
		RsaKey.GenerateKeyFile();
		Assert.False(RsaKey.ReadKeyFromFile($"{Cryptography.Rsa.ToLower()}_private_key.pem").IsInvalid);
		
		File.Delete($"{Cryptography.Rsa.ToLower()}_private_key.pem");
	}
}