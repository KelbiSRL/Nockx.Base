using Nockx.Base.CryptographyTypes;

namespace Nockx.BaseTest.NockxKeyTests;

public class SignVerifyTests {
	[Fact]
	public void SignVerifySuccess() {
		using NockxKey key = NockxKey.ReadKeyFromFile("nockxtestkey.pem");
		Assert.True(key.Verify(key.Sign([.."hello"u8]), [.."hello"u8]));
	}
	
	[Fact]
	public void SignVerifyWrongDataFail() {
		using NockxKey key = NockxKey.ReadKeyFromFile("nockxtestkey.pem");
		Assert.False(key.Verify(key.Sign([.."hello"u8]), [.."helo"u8]));
	}
	
	[Fact]
	public void SignVerifyWrongKeyFail() {
		using NockxKey key = NockxKey.ReadKeyFromFile("nockxtestkey.pem");
		using NockxKey key2 = NockxKey.ReadKeyFromFile("nockxtestkey2.pem");
		Assert.False(key2.Verify(key.Sign([.."hello"u8]), [.."hello"u8]));
	}
	
	[Fact]
	public void SignVerifyWrongRsaKeyFail() {
		using NockxKey key = NockxKey.ReadKeyFromFile("nockxtestkey.pem");
		using NockxKey key2 = NockxKey.ReadKeyFromFile("nockxwrongrsatestkey.pem");
		Assert.False(key2.Verify(key.Sign([.."hello"u8]), [.."hello"u8]));
	}
	
	[Fact]
	public void SignVerifyWrongMlDsaKeyFail() {
		using NockxKey key = NockxKey.ReadKeyFromFile("nockxtestkey.pem");
		using NockxKey key2 = NockxKey.ReadKeyFromFile("nockxwrongmldsatestkey.pem");
		Assert.False(key2.Verify(key.Sign([.."hello"u8]), [.."hello"u8]));
	}
}