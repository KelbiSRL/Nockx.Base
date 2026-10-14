using Nockx.Base.CryptographyTypes.Aes;

namespace Nockx.BaseTest.AesKeyTests;

public class GenerateTests {
	[Fact]
	public void GenerateSuccess() {
		using AesKey aesKey = AesKey.Generate();
		Assert.False(aesKey.IsInvalid);
	}
}