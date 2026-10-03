using Nockx.Base.CryptographyTypes.Aes;

namespace Nockx.BaseTest.AesKeyTests;

public class GenerateTests {
	[Fact]
	public void GenerateSuccess() => Assert.False(AesKey.Generate().IsInvalid);
}