using Nockx.Base.CryptographyTypes.MlDsa;

namespace Nockx.BaseTest.MlDsaPublicKeyTests;

public class ComparisonTests {
	[Fact]
	public void KeysEqual() {
		using MlDsaKey key1 = MlDsaKey.ReadKeyFromFile("nockxtestkey.pem");
		using MlDsaKey key2 = MlDsaKey.ReadKeyFromFile("nockxtestkey.pem");
		
		Assert.True(key1.Public == key2.Public);
		Assert.False(key1.Public != key2.Public);
		Assert.Equal(key1.Public, key2.Public);
	}
	
	[Fact]
	public void KeysNotEqual() {
		using MlDsaKey key1 = MlDsaKey.ReadKeyFromFile("nockxtestkey.pem");
		using MlDsaKey key2 = MlDsaKey.ReadKeyFromFile("nockxtestkey2.pem");
		
		Assert.True(key1.Public != key2.Public);
		Assert.False(key1.Public == key2.Public);
		Assert.NotEqual(key1.Public, key2.Public);
	}

	[Fact]
	public void KeyEqualString() {
		using MlDsaKey key = MlDsaKey.ReadKeyFromFile("nockxtestkey.pem");
		const string keyString = "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";
		
		Assert.True(key.Public == keyString);
		Assert.True(keyString == key.Public);
		Assert.False(key.Public != keyString);
		Assert.False(keyString != key.Public);
		Assert.Equal(key.Public, keyString);
		Assert.Equal(keyString, key.Public);
	}
	
	[Fact]
	public void KeyNotEqualString() {
		using MlDsaKey key = MlDsaKey.ReadKeyFromFile("nockxtestkey2.pem");
		const string keyString = "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";
		
		Assert.True(key.Public != keyString);
		Assert.True(keyString != key.Public);
		Assert.False(key.Public == keyString);
		Assert.False(keyString == key.Public);
		Assert.NotEqual(key.Public, keyString);
		Assert.NotEqual(keyString, key.Public);
	}

	[Fact]
	public void KeyNotNull() {
		using MlDsaKey key = MlDsaKey.ReadKeyFromFile("nockxtestkey.pem");
		MlDsaPublicKey? publicKey = null;
		
		Assert.True(key.Public != publicKey);
		Assert.True(publicKey != key.Public);
		Assert.False(key.Public == publicKey);
		Assert.False(publicKey == key.Public);
		Assert.NotEqual(publicKey, key.Public);
		Assert.NotEqual(key.Public, publicKey);
	}
	
	[Fact]
	public void KeyNull() {
		MlDsaPublicKey? publicKey = null;
		MlDsaPublicKey? publicKey2 = null;
		
		Assert.True(publicKey2 == publicKey);
		Assert.True(publicKey == publicKey2);
		Assert.False(publicKey2 != publicKey);
		Assert.False(publicKey != publicKey2);
		Assert.Equal(publicKey, publicKey2);
		Assert.Equal(publicKey2, publicKey);
	}
}