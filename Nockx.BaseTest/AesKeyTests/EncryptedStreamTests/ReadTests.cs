using System.Text;
using Nockx.Base;
using Nockx.Base.CryptographyTypes.Aes;

namespace Nockx.BaseTest.AesKeyTests.EncryptedStreamTests;

public class ReadTests {
	[Fact]
	public void ReadSuccess() {
		const string input = "fjapjfombvlxnvowahflxvbkwoqhflfqpjfqpowufoeiphljxbnvmxqpfjzpjdnvcz.nm.fqewpriu1p";
		using MemoryStream inputStream = new (Encoding.UTF8.GetBytes(input));
		using AesKey aesKey = AesKey.Generate();
		using EncryptedStream encryptedStream = new (inputStream, aesKey, true);

		using MemoryStream intermediaryStream = new ();
		int read;
		byte[] buffer = new byte[1024];
		while ((read = encryptedStream.Read(buffer, 0, buffer.Length)) > 0)
			intermediaryStream.Write(buffer, 0, read);
		
		intermediaryStream.Position = 0;
		using EncryptedStream decryptionStream = new (intermediaryStream, aesKey, false, iv: encryptedStream.Iv);
		using MemoryStream decryptedStream = new ();
		while ((read = decryptionStream.Read(buffer, 0, buffer.Length)) > 0)
			decryptedStream.Write(buffer, 0, read);
		
		Assert.Equal(input, Encoding.UTF8.GetString(decryptedStream.ToArray()));
	}
}