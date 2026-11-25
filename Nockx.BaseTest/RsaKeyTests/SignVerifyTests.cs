using Nockx.Base.CryptographyTypes.Aes;
using Nockx.Base.CryptographyTypes.Rsa;

namespace Nockx.BaseTest.RsaKeyTests;

public class SignVerifyTests {
	[Fact]
	public void SignVerifySuccess() {
		using RsaKey key = RsaKey.ReadKeyFromFile("rsatestkey.pem");
		Assert.True(key.Verify(key.Sign([.."hello"u8]), [.."hello"u8]));
	}
	
	[Fact]
	public void SignVerifyAesKeySuccess() {
		using AesKey aesKey = AesKey.Generate();
		using RsaKey key = RsaKey.ReadKeyFromFile("rsatestkey.pem");
		Assert.True(key.Verify(key.Sign([.."hello"u8], [aesKey]), [.."hello"u8], [aesKey]));
	}
	
	[Fact]
	public void SignVerifyMultipleAesKeysSuccess() {
		using AesKey aesKey = AesKey.Generate();
		using AesKey aesKey2 = AesKey.Generate();
		using RsaKey key = RsaKey.ReadKeyFromFile("rsatestkey.pem");
		Assert.True(key.Verify(key.Sign([.."hello"u8], [aesKey, aesKey2]), [.."hello"u8], [aesKey, aesKey2]));
	}
	
	[Fact]
	public void SignVerifyWrongDataFail() {
		using RsaKey key = RsaKey.ReadKeyFromFile("rsatestkey.pem");
		Assert.False(key.Verify(key.Sign([.."hello"u8]), [.."helo"u8]));
	}
	
	[Fact]
	public void SignVerifyWrongKeyFail() {
		using RsaKey key = RsaKey.ReadKeyFromFile("rsatestkey.pem");
		using RsaKey key2 = RsaKey.ReadKeyFromFile("rsatestkey2.pem");
		Assert.False(key2.Verify(key.Sign([.."hello"u8]), [.."hello"u8]));
	}
	
	[Fact]
	public void SignVerifyNoAesKeyFail() {
		using AesKey aesKey = AesKey.Generate();
		using RsaKey key = RsaKey.ReadKeyFromFile("rsatestkey.pem");
		Assert.False(key.Verify(key.Sign([.."hello"u8], [aesKey]), [.."hello"u8]));
	}
	
	[Fact]
	public void SignVerifyWrongAesKeyFail() {
		using AesKey aesKey = AesKey.Generate();
		using AesKey aesKey2 = AesKey.Generate();
		using RsaKey key = RsaKey.ReadKeyFromFile("rsatestkey.pem");
		Assert.False(key.Verify(key.Sign([.."hello"u8], [aesKey]), [.."hello"u8], [aesKey2]));
	}
}