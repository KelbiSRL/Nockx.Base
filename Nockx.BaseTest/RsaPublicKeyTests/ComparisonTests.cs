using Nockx.Base.CryptographyTypes.Rsa;

namespace Nockx.BaseTest.RsaPublicKeyTests;

public class ComparisonTests {
	[Fact]
	public void KeysEqual() {
		using RsaKey key1 = RsaKey.ReadKeyFromFile("nockxtestkey.pem");
		using RsaKey key2 = RsaKey.ReadKeyFromFile("nockxtestkey.pem");
		
		Assert.True(key1.Public == key2.Public);
		Assert.False(key1.Public != key2.Public);
		Assert.Equal(key1.Public, key2.Public);
	}
	
	[Fact]
	public void KeysNotEqual() {
		using RsaKey key1 = RsaKey.ReadKeyFromFile("nockxtestkey.pem");
		using RsaKey key2 = RsaKey.ReadKeyFromFile("nockxtestkey2.pem");
		
		Assert.True(key1.Public != key2.Public);
		Assert.False(key1.Public == key2.Public);
		Assert.NotEqual(key1.Public, key2.Public);
	}

	[Fact]
	public void KeyEqualString() {
		using RsaKey key = RsaKey.ReadKeyFromFile("nockxtestkey.pem");
		const string keyString = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAitgFbz29foUeJhrpTsKU8TXkp0+dMaJGftcx+bcTEa6M2KbO/A160qooJqhOAwtoFpidAOyrfAQYj6ZCCjpFF2S4p/wsw+FyQX1/dmb2Xcsc+Oh72YPMEl2Q9b8QnasXGL+J6ECQeOjAaaN6vX420Y9LQlnk9NVnQJcqnG8Dqrln8KigpIoSmoYzP5aahajTzNgT9oFPxq1L7ndjvtsp2ndjTpsy3b5n9SdDv3VafGtGfVb6yBLmPOdADc3CeP+YxvSBnCmIcl66LQADmlQlIMFN1y/AyAzfbBGkwlnSbjoSqexDW43TEhwpF/xktYpUvhQtnIZRMTJT0dPv0lzktwIDAQAB";
		
		Assert.True(key.Public == keyString);
		Assert.True(keyString == key.Public);
		Assert.False(key.Public != keyString);
		Assert.False(keyString != key.Public);
		Assert.Equal(key.Public, keyString);
		Assert.Equal(keyString, key.Public);
	}
	
	[Fact]
	public void KeyNotEqualString() {
		using RsaKey key = RsaKey.ReadKeyFromFile("nockxtestkey2.pem");
		const string keyString = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAitgFbz29foUeJhrpTsKU8TXkp0+dMaJGftcx+bcTEa6M2KbO/A160qooJqhOAwtoFpidAOyrfAQYj6ZCCjpFF2S4p/wsw+FyQX1/dmb2Xcsc+Oh72YPMEl2Q9b8QnasXGL+J6ECQeOjAaaN6vX420Y9LQlnk9NVnQJcqnG8Dqrln8KigpIoSmoYzP5aahajTzNgT9oFPxq1L7ndjvtsp2ndjTpsy3b5n9SdDv3VafGtGfVb6yBLmPOdADc3CeP+YxvSBnCmIcl66LQADmlQlIMFN1y/AyAzfbBGkwlnSbjoSqexDW43TEhwpF/xktYpUvhQtnIZRMTJT0dPv0lzktwIDAQAB";
		
		Assert.True(key.Public != keyString);
		Assert.True(keyString != key.Public);
		Assert.False(key.Public == keyString);
		Assert.False(keyString == key.Public);
		Assert.NotEqual(key.Public, keyString);
		Assert.NotEqual(keyString, key.Public);
	}

	[Fact]
	public void KeyNotNull() {
		using RsaKey key = RsaKey.ReadKeyFromFile("nockxtestkey.pem");
		RsaPublicKey? publicKey = null;
		
		Assert.True(key.Public != publicKey);
		Assert.True(publicKey != key.Public);
		Assert.False(key.Public == publicKey);
		Assert.False(publicKey == key.Public);
		Assert.NotEqual(publicKey, key.Public);
		Assert.NotEqual(key.Public, publicKey);
	}
	
	[Fact]
	public void KeyNull() {
		RsaPublicKey? publicKey = null;
		RsaPublicKey? publicKey2 = null;
		
		Assert.True(publicKey2 == publicKey);
		Assert.True(publicKey == publicKey2);
		Assert.False(publicKey2 != publicKey);
		Assert.False(publicKey != publicKey2);
		Assert.Equal(publicKey, publicKey2);
		Assert.Equal(publicKey2, publicKey);
	}
}