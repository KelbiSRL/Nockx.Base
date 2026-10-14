using Nockx.Base.CryptographyTypes.MlDsa;

namespace Nockx.BaseTest.MlDsaKeyTests;

public class SignVerifyTests {
	[Fact]
	public void SignVerifySuccess() {
		using MlDsaKey key = MlDsaKey.ReadKeyFromFile("mldsatestkey.pem");
		Assert.True(key.Verify(key.Sign([.."hello"u8]), [.."hello"u8]));
	}
	
	[Fact]
	public void SignVerifyWrongDataFail() {
		using MlDsaKey key = MlDsaKey.ReadKeyFromFile("mldsatestkey.pem");
		Assert.False(key.Verify(key.Sign([.."hello"u8]), [.."helo"u8]));
	}
	
	[Fact]
	public void SignVerifyWrongKeyFail() {
		using MlDsaKey key = MlDsaKey.ReadKeyFromFile("mldsatestkey.pem");
		using MlDsaKey key2 = MlDsaKey.ReadKeyFromFile("mldsatestkey2.pem");
		Assert.False(key2.Verify(key.Sign([.."hello"u8]), [.."hello"u8]));
	}
}