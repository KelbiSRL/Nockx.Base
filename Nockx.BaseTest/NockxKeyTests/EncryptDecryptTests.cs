using System.Text;
using Nockx.Base.CryptographyTypes;
using Nockx.Base.NockxKeyDataStorageTypes;

namespace Nockx.BaseTest.NockxKeyTests;

public class EncryptDecryptTests {
	[Fact]
	public void EncryptDecryptSuccess() {
		const string input = "Hello";
		
		NockxKey nockxKey = NockxKey.ReadKeyFromFile("nockxtestkey.pem");
		Assert.Equal(input, Encoding.UTF8.GetString(nockxKey.DecryptBytes(nockxKey.EncryptBytes(Encoding.UTF8.GetBytes(input)))));
	}
	
	// TODO: this should be tested with individual wrong keys too, not just with the whole combined key being wrong
	[Fact]
	public void EncryptDecryptWrongKeyFail() {
		const string input = "Hello";
		
		NockxKey nockxKey = NockxKey.ReadKeyFromFile("nockxtestkey.pem");
		NockxKey nockxKey2 = NockxKey.ReadKeyFromFile("nockxtestkey2.pem");
		EncryptedKeyDataPair encryptedData = nockxKey.EncryptBytes(Encoding.UTF8.GetBytes(input));
		Assert.Throws<InvalidOperationException>(() => nockxKey2.DecryptBytes(encryptedData));
	}
}