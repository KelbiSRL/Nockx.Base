using Nockx.Base.CryptographyTypes;

namespace Nockx.BaseTest.NockxKeyTests;

public class SignVerifyTests {
	[Fact]
	public void SignVerifySuccess() {
		NockxKey key = NockxKey.ReadKeyFromFile("nockxtestkey.pem");
		Assert.True(key.Verify(key.Sign([.."hello"u8]), [.."hello"u8]));
	}
	
	[Fact]
	public void SignVerifyWrongDataFail() {
		NockxKey key = NockxKey.ReadKeyFromFile("nockxtestkey.pem");
		Assert.False(key.Verify(key.Sign([.."hello"u8]), [.."helo"u8]));
	}
	
	// TODO: this should be tested with individual wrong keys too, not just with the whole combined key being wrong
	[Fact]
	public void SignVerifyWrongKeyFail() {
		NockxKey key = NockxKey.ReadKeyFromFile("nockxtestkey.pem");
		NockxKey key2 = NockxKey.ReadKeyFromFile("nockxtestkey2.pem");
		Assert.False(key2.Verify(key.Sign([.."hello"u8]), [.."hello"u8]));
	}
}