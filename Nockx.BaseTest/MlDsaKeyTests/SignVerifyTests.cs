using Nockx.Base.CryptographyTypes.Aes;
using Nockx.Base.CryptographyTypes.MlDsa;

namespace Nockx.BaseTest.MlDsaKeyTests;

public class SignVerifyTests {
	[Fact]
	public void SignVerifySuccess() {
		using MlDsaKey key = MlDsaKey.ReadKeyFromFile("mldsatestkey.pem");
		Assert.True(key.Verify(key.Sign([.."hello"u8]), [.."hello"u8]));
	}
	
	[Fact]
	public void SignVerifyAesKeySuccess() {
		using AesKey aesKey = AesKey.Generate();
		using MlDsaKey key = MlDsaKey.ReadKeyFromFile("mldsatestkey.pem");
		Assert.True(key.Verify(key.Sign([.."hello"u8], [aesKey]), [.."hello"u8], [aesKey]));
	}
	
	[Fact]
	public void SignVerifyMultipleAesKeysSuccess() {
		using AesKey aesKey = AesKey.Generate();
		using AesKey aesKey2 = AesKey.Generate();
		using MlDsaKey key = MlDsaKey.ReadKeyFromFile("mldsatestkey.pem");
		Assert.True(key.Verify(key.Sign([.."hello"u8], [aesKey, aesKey2]), [.."hello"u8], [aesKey, aesKey2]));
	}
	
	[Fact]
	public void SignVerifyWrongDataFail() {
		using MlDsaKey key = MlDsaKey.ReadKeyFromFile("mldsatestkey.pem");
		Assert.False(key.Verify(key.Sign([.."hello"u8]), [.."helo"u8]));
	}
	
	[Fact]
	public void SignVerifyWrongDataWithAesKeyFail() {
		using AesKey aesKey = AesKey.Generate();
		using MlDsaKey key = MlDsaKey.ReadKeyFromFile("mldsatestkey.pem");
		Assert.False(key.Verify(key.Sign([.."hello"u8], [aesKey]), [.."helo"u8], [aesKey]));
	}
	
	[Fact]
	public void SignVerifyWrongKeyFail() {
		using MlDsaKey key = MlDsaKey.ReadKeyFromFile("mldsatestkey.pem");
		using MlDsaKey key2 = MlDsaKey.ReadKeyFromFile("mldsatestkey2.pem");
		Assert.False(key2.Verify(key.Sign([.."hello"u8]), [.."hello"u8]));
	}
	
	[Fact]
	public void SignVerifyNoAesKeyFail() {
		using AesKey aesKey = AesKey.Generate();
		using MlDsaKey key = MlDsaKey.ReadKeyFromFile("mldsatestkey.pem");
		Assert.False(key.Verify(key.Sign([.."hello"u8], [aesKey]), [.."hello"u8]));
	}
	
	[Fact]
	public void SignVerifyWrongAesKeyFail() {
		using AesKey aesKey = AesKey.Generate();
		using AesKey aesKey2 = AesKey.Generate();
		using MlDsaKey key = MlDsaKey.ReadKeyFromFile("mldsatestkey.pem");
		Assert.False(key.Verify(key.Sign([.."hello"u8], [aesKey]), [.."hello"u8], [aesKey2]));
	}
}