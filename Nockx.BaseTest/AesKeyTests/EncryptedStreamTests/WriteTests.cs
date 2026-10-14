using System.Text;
using Nockx.Base;
using Nockx.Base.CryptographyTypes.Aes;

namespace Nockx.BaseTest.AesKeyTests.EncryptedStreamTests;

public class WriteTests {
	[Fact]
	public void WriteSuccess() {
		const string input = "fjapjfombvlxnvowahflxvbkwoqhflfqpjfqpowufoeiphljxbnvmxqpfjzpjdnvcz.nm.fqewpriu1p";
		using MemoryStream inputStream = new (Encoding.UTF8.GetBytes(input));
		
		using MemoryStream intermediaryStream = new ();
		using AesKey aesKey = AesKey.Generate();
		using EncryptedStream encryptedStream = new (intermediaryStream, aesKey, true);
		
		int read;
		byte[] buffer = new byte[1024];
		while ((read = inputStream.Read(buffer, 0, buffer.Length)) > 0)
			encryptedStream.Write(buffer, 0, read);
		
		intermediaryStream.Position = 0;
		using MemoryStream decryptedStream = new ();
		using EncryptedStream decryptionStream = new (decryptedStream, aesKey, false, iv: encryptedStream.Iv);
		while ((read = intermediaryStream.Read(buffer, 0, buffer.Length)) > 0)
			decryptionStream.Write(buffer, 0, read);
		
		Assert.Equal(input, Encoding.UTF8.GetString(decryptedStream.ToArray()));
	}
}