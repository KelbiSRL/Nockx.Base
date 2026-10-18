using System.Text;
using Nockx.Base;
using Nockx.Base.CryptographyTypes.Aes;

namespace Nockx.BaseTest.AesKeyTests.EncryptedStreamTests;

public class MemoryManagementTests {
	[Fact]
	public void ObjectDisposedFail() {
		const string input = "fjapjfombvlxnvowahflxvbkwoqhflfqpjfqpowufoeiphljxbnvmxqpfjzpjdnvcz.nm.fqewpriu1p";
		using MemoryStream inputStream = new (Encoding.UTF8.GetBytes(input));
		using AesKey aesKey = AesKey.Generate();
		EncryptedStream encryptedStream = new (inputStream, aesKey, true);
		encryptedStream.Dispose();
		
		Assert.Throws<ObjectDisposedException>(() => encryptedStream.ReadByte());
		Assert.Throws<ObjectDisposedException>(() => inputStream.ReadByte());
	}
}