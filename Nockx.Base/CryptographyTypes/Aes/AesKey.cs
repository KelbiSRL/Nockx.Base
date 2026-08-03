using System.Runtime.InteropServices;

namespace Nockx.Base.CryptographyTypes.Aes;

public class AesKey : SafeHandle {
	private const int IvLength = 12;
	
	public override bool IsInvalid => handle == IntPtr.Zero;

	/**
	 * Creating an instance of <see cref="AesKey"/> does not yield a valid instance. Use <see cref="Generate">AesKey.Generate</see>
	 */
	public AesKey() : base(IntPtr.Zero, true) { }

	public static AesKey Generate() {
		AesKey aesKey = AesCryptography.create_aes_key();
		return aesKey.IsInvalid ? throw new InvalidOperationException("AesKey could not be created") : aesKey;
	}

	public unsafe byte[] Encrypt(byte[] data, byte[]? additionalAuthenticationData = null) {
		byte[] iv = new byte[IvLength];
		
		fixed (byte *ivPtr = iv)
			if (AesCryptography.generate_iv(ivPtr) != 1)
				throw new InvalidOperationException("IV could not be generated");
		
		return Encrypt(data, iv, additionalAuthenticationData);
	}
	
	public unsafe byte[] Encrypt(byte[] data, byte[] iv, byte[]? additionalAuthenticationData) {
		additionalAuthenticationData ??= [];
		
		ulong ciphertextLength;
		IntPtr ciphertextPointer = AesCryptography.encrypt_with_aes_gcm(data, (ulong) data.LongLength, this, iv, additionalAuthenticationData, (ulong) additionalAuthenticationData.LongLength, &ciphertextLength);
		if (ciphertextPointer == IntPtr.Zero)
			throw new InvalidOperationException("Data could not be encrypted with AES-GCM");

		byte[] ciphertext = new byte[IvLength + ciphertextLength];
		Buffer.BlockCopy(iv, 0, ciphertext, 0, IvLength);
		fixed (byte *ciphertextPtr = ciphertext)
			Buffer.MemoryCopy((void *) ciphertextPointer, ciphertextPtr + IvLength, ciphertextLength, ciphertextLength);
		
		HelperFunctions.free_openssl_pointer((void *) ciphertextPointer);
		
		return ciphertext;
	}
	
	public unsafe byte[] Decrypt(byte[] data, byte[]? additionalAuthenticationData = null) {
		additionalAuthenticationData ??= [];
		
		byte[] iv = new byte[IvLength];
		Buffer.BlockCopy(data, 0, iv, 0, IvLength);
		
		ulong plaintextLength;
		IntPtr plaintextPointer = AesCryptography.decrypt_with_aes_gcm(data[IvLength..], (ulong) data.LongLength - IvLength, this, iv, additionalAuthenticationData, (ulong) additionalAuthenticationData.LongLength, &plaintextLength);
		if (plaintextPointer == IntPtr.Zero)
			throw new InvalidOperationException("Data could not be decrypted with AES-GCM");

		byte[] plaintext = new byte[plaintextLength];
		fixed (byte *plaintextPtr = plaintext)
			Buffer.MemoryCopy((void *) plaintextPointer, plaintextPtr, plaintextLength, plaintextLength);
		
		HelperFunctions.free_openssl_pointer((void *) plaintextPointer);
		
		return plaintext;
	}
	
	protected override bool ReleaseHandle() {
		AesCryptography.destroy_aes_key(this);
		return true;
	}
}