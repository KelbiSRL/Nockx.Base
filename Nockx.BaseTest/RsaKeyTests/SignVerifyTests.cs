using Nockx.Base.CryptographyTypes.Rsa;

namespace Nockx.BaseTest.RsaKeyTests;

public class SignVerifyTests {
	[Fact]
	public void SignVerifySuccess() {
		RsaKey key = RsaKey.ReadKeyFromFile("rsatestkey.pem");
		Assert.True(key.Verify(key.Sign([.."hello"u8]), [.."hello"u8]));
	}
	
	[Fact]
	public void SignVerifyWrongDataFail() {
		RsaKey key = RsaKey.ReadKeyFromFile("rsatestkey.pem");
		Assert.False(key.Verify(key.Sign([.."hello"u8]), [.."helo"u8]));
	}
	
	[Fact]
	public void SignVerifyWrongKeyFail() {
		RsaKey key = RsaKey.ReadKeyFromFile("rsatestkey.pem");
		RsaKey key2 = RsaKey.ReadKeyFromFile("rsatestkey2.pem");
		Assert.False(key2.Verify(key.Sign([.."hello"u8]), [.."hello"u8]));
	}
}