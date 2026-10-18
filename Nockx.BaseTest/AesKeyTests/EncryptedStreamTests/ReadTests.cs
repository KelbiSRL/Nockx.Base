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

		byte[] tag = encryptedStream.CalculateTag();
		
		intermediaryStream.Position = 0;
		using EncryptedStream decryptionStream = new (intermediaryStream, aesKey, false, iv: encryptedStream.Iv);
		using MemoryStream decryptedStream = new ();
		while ((read = decryptionStream.Read(buffer, 0, buffer.Length)) > 0)
			decryptedStream.Write(buffer, 0, read);
		
		Assert.True(decryptionStream.VerifyTag(tag));
		Assert.Equal(input, Encoding.UTF8.GetString(decryptedStream.ToArray()));
	}

	[Fact]
	public void InterruptedReadSuccess() {
		const string input = "fjapjfombvlxnvowahflxvbkwoqhflfqpjfqpowufoeiphljxbnvmxqpfjzpjdnvcz.nm.fqewpriu1p";
		using MemoryStream inputStream = new (Encoding.UTF8.GetBytes(input));
		using AesKey aesKey = AesKey.Generate();
		
		using MemoryStream intermediaryStream = new ();
		byte[] iv;
		using (EncryptedStream encryptedStream = new (inputStream, aesKey, true)) {
			iv = encryptedStream.Iv;
			int read;
			byte[] buffer = new byte[20];
			if ((read = encryptedStream.Read(buffer, 0, buffer.Length)) > 0)
				intermediaryStream.Write(buffer, 0, read);
			
			Assert.Equal(20, encryptedStream.Position);
		}

		using MemoryStream inputStream2 = new (Encoding.UTF8.GetBytes(input));
		using EncryptedStream encryptedStream2 = new (inputStream2, aesKey, true, iv: iv);
		encryptedStream2.ReadAndDiscard(intermediaryStream.Position);
		int read2;
		byte[] buffer2 = new byte[20];
		while ((read2 = encryptedStream2.Read(buffer2, 0, buffer2.Length)) > 0)
			intermediaryStream.Write(buffer2, 0, read2);

		byte[] tag = encryptedStream2.CalculateTag();

		intermediaryStream.Position = 0;
		using EncryptedStream decryptionStream = new (intermediaryStream, aesKey, false, iv: iv);
		using MemoryStream decryptedStream = new ();
		while ((read2 = decryptionStream.Read(buffer2, 0, buffer2.Length)) > 0)
			decryptedStream.Write(buffer2, 0, read2);
		
		Assert.True(decryptionStream.VerifyTag(tag));
		Assert.Equal(input, Encoding.UTF8.GetString(decryptedStream.ToArray()));
	}

	[Fact]
	public void ReadWithAadSuccess() {
		const string input = "fjapjfombvlxnvowahflxvbkwoqhflfqpjfqpowufoeiphljxbnvmxqpfjzpjdnvcz.nm.fqewpriu1p";
		using MemoryStream inputStream = new (Encoding.UTF8.GetBytes(input));
		using AesKey aesKey = AesKey.Generate();
		using EncryptedStream encryptedStream = new (inputStream, aesKey, true, aad: [.."hello"u8]);

		using MemoryStream intermediaryStream = new ();
		int read;
		byte[] buffer = new byte[1024];
		while ((read = encryptedStream.Read(buffer, 0, buffer.Length)) > 0)
			intermediaryStream.Write(buffer, 0, read);

		byte[] tag = encryptedStream.CalculateTag();
		
		intermediaryStream.Position = 0;
		using EncryptedStream decryptionStream = new (intermediaryStream, aesKey, false, iv: encryptedStream.Iv, aad: [.."hello"u8]);
		using MemoryStream decryptedStream = new ();
		while ((read = decryptionStream.Read(buffer, 0, buffer.Length)) > 0)
			decryptedStream.Write(buffer, 0, read);
		
		Assert.True(decryptionStream.VerifyTag(tag));
		Assert.Equal(input, Encoding.UTF8.GetString(decryptedStream.ToArray()));
	}
	
	[Fact]
	public void ReadWithWrongAadFail() {
		const string input = "fjapjfombvlxnvowahflxvbkwoqhflfqpjfqpowufoeiphljxbnvmxqpfjzpjdnvcz.nm.fqewpriu1p";
		using MemoryStream inputStream = new (Encoding.UTF8.GetBytes(input));
		using AesKey aesKey = AesKey.Generate();
		using EncryptedStream encryptedStream = new (inputStream, aesKey, true, aad: [.."hello"u8]);

		using MemoryStream intermediaryStream = new ();
		int read;
		byte[] buffer = new byte[1024];
		while ((read = encryptedStream.Read(buffer, 0, buffer.Length)) > 0)
			intermediaryStream.Write(buffer, 0, read);

		byte[] tag = encryptedStream.CalculateTag();
		
		intermediaryStream.Position = 0;
		using EncryptedStream decryptionStream = new (intermediaryStream, aesKey, false, iv: encryptedStream.Iv, aad: [.."helo"u8]);
		using MemoryStream decryptedStream = new ();
		while ((read = decryptionStream.Read(buffer, 0, buffer.Length)) > 0)
			decryptedStream.Write(buffer, 0, read);
		
		Assert.False(decryptionStream.VerifyTag(tag));
		Assert.Equal(input, Encoding.UTF8.GetString(decryptedStream.ToArray()));
	}
	
	[Fact]
	public void ReadWithNoAadFail() {
		const string input = "fjapjfombvlxnvowahflxvbkwoqhflfqpjfqpowufoeiphljxbnvmxqpfjzpjdnvcz.nm.fqewpriu1p";
		using MemoryStream inputStream = new (Encoding.UTF8.GetBytes(input));
		using AesKey aesKey = AesKey.Generate();
		using EncryptedStream encryptedStream = new (inputStream, aesKey, true, aad: [.."hello"u8]);

		using MemoryStream intermediaryStream = new ();
		int read;
		byte[] buffer = new byte[1024];
		while ((read = encryptedStream.Read(buffer, 0, buffer.Length)) > 0)
			intermediaryStream.Write(buffer, 0, read);

		byte[] tag = encryptedStream.CalculateTag();
		
		intermediaryStream.Position = 0;
		using EncryptedStream decryptionStream = new (intermediaryStream, aesKey, false, iv: encryptedStream.Iv);
		using MemoryStream decryptedStream = new ();
		while ((read = decryptionStream.Read(buffer, 0, buffer.Length)) > 0)
			decryptedStream.Write(buffer, 0, read);
		
		Assert.False(decryptionStream.VerifyTag(tag));
		Assert.Equal(input, Encoding.UTF8.GetString(decryptedStream.ToArray()));
	}
	
	[Fact]
	public void ReadWithNonExistingAadFail() {
		const string input = "fjapjfombvlxnvowahflxvbkwoqhflfqpjfqpowufoeiphljxbnvmxqpfjzpjdnvcz.nm.fqewpriu1p";
		using MemoryStream inputStream = new (Encoding.UTF8.GetBytes(input));
		using AesKey aesKey = AesKey.Generate();
		using EncryptedStream encryptedStream = new (inputStream, aesKey, true);

		using MemoryStream intermediaryStream = new ();
		int read;
		byte[] buffer = new byte[1024];
		while ((read = encryptedStream.Read(buffer, 0, buffer.Length)) > 0)
			intermediaryStream.Write(buffer, 0, read);

		byte[] tag = encryptedStream.CalculateTag();
		
		intermediaryStream.Position = 0;
		using EncryptedStream decryptionStream = new (intermediaryStream, aesKey, false, iv: encryptedStream.Iv, aad: [.."hello"u8]);
		using MemoryStream decryptedStream = new ();
		while ((read = decryptionStream.Read(buffer, 0, buffer.Length)) > 0)
			decryptedStream.Write(buffer, 0, read);
		
		Assert.False(decryptionStream.VerifyTag(tag));
		Assert.Equal(input, Encoding.UTF8.GetString(decryptedStream.ToArray()));
	}
}