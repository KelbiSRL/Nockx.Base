using System.Text;
using Nockx.Base.CryptographyTypes.Aes;

namespace Nockx.BaseTest.AesKeyTests;

public class EncryptDecryptTests {
	// TODO: could do a check for pure encryption by getting an rsa key, encrypted aes key and known output of that aes key
	
	[Fact]
	public void EncryptDecryptSuccess() {
		AesKey key = AesKey.Generate();
		const string input = "Hello, this is a test.";
		Assert.Equal(input, Encoding.UTF8.GetString(key.Decrypt(key.Encrypt(Encoding.UTF8.GetBytes(input)))));
	}
	
	[Fact]
	public void EncryptDecryptIvSuccess() {
		AesKey key = AesKey.Generate();
		const string input = "Hello, this is a test.";
		Assert.Equal(input, Encoding.UTF8.GetString(key.Decrypt(key.Encrypt(Encoding.UTF8.GetBytes(input), [1,2,3,4,5,6,7,8,9,10,11,12], null))));
	}

	[Fact]
	public void EncryptDecryptAadSuccess() {
		AesKey key = AesKey.Generate();
		const string input = "Hello, this is a test.";
		const string aad = "name=Alice";
		Assert.Equal(input, Encoding.UTF8.GetString(key.Decrypt(key.Encrypt(Encoding.UTF8.GetBytes(input), Encoding.UTF8.GetBytes(aad)), Encoding.UTF8.GetBytes(aad))));
	}
	
	[Fact]
	public void EncryptDecryptWrongKeyFail() {
		AesKey key = AesKey.Generate();
		AesKey key2 = AesKey.Generate();
		const string input = "Hello, this is a test.";
		Assert.Throws<InvalidOperationException>(() => key2.Decrypt(key.Encrypt(Encoding.UTF8.GetBytes(input))));
	}

	[Fact]
	public void EncryptDecryptWrongAadFail() {
		AesKey key = AesKey.Generate();
		const string input = "Hello, this is a test.";
		const string aad = "name=Alice";
		Assert.Throws<InvalidOperationException>(() => key.Decrypt(key.Encrypt(Encoding.UTF8.GetBytes(input), Encoding.UTF8.GetBytes(aad)), [.."name=notalice"u8]));
	}
	
	[Fact]
	public void EncryptDecryptIvTooShortFail() {
		AesKey key = AesKey.Generate();
		const string input = "Hello, this is a test.";
		Assert.Throws<ArgumentOutOfRangeException>(() => key.Encrypt(Encoding.UTF8.GetBytes(input), [1,2,3,4,5,6,7,8,9,10,11], null));
	}
	
	[Fact]
	public void EncryptDecryptIvTooLongFail() {
		AesKey key = AesKey.Generate();
		const string input = "Hello, this is a test.";
		Assert.Throws<ArgumentOutOfRangeException>(() => key.Encrypt(Encoding.UTF8.GetBytes(input), [1,2,3,4,5,6,7,8,9,10,11,12,13], null));
	}
}