using Nockx.Base.CryptographyTypes.Aes;

namespace Nockx.Base.CryptographyTypes.Rsa;

public sealed class RsaKey : AsymmetricKey {
	internal const string KeyType = "RSA";
	
	private protected override string InstanceKeyType => KeyType;
	
	public new RsaPublicKey Public => (RsaPublicKey) base.Public;

	public RsaKey() {
		
	}

	public static void GenerateKeyFile() {
		if (HelperFunctions.generate_key(KeyType) == 0)
			throw new InvalidOperationException("RSA key file could not be generated");
	}

	public static RsaKey ReadKeyFromFile(string fileName) {
		RsaKey rsaKey = HelperFunctions.ReadRsaKeyFromFile(fileName);
		return rsaKey.IsInvalid ? throw new InvalidOperationException("RSA private key could not be read") : rsaKey;
	}
	
	public byte[] EncryptAesKey(AesKey aesKey) => Public.EncryptAesKey(aesKey);
	
	public AesKey DecryptAesKey(byte[] data) {
		AesKey aesKey = RsaCryptography.decrypt_aes_key_with_rsa(this, data, (uint) data.Length);
		return aesKey.IsInvalid ? throw new InvalidOperationException("AES key could not be decrypted with RSA") : aesKey;
	}

	public unsafe byte[] Sign(byte[] data) {
		ulong signatureSize;
		IntPtr signaturePointer = RsaCryptography.sign_with_rsa(this, data, (ulong) data.LongLength, &signatureSize);
		if (signaturePointer == IntPtr.Zero)
			throw new InvalidOperationException("Data could not be signed with RSA");

		byte[] signature = new byte[signatureSize];
		fixed (byte *signaturePtr = signature)
			Buffer.MemoryCopy((void *) signaturePointer, signaturePtr, signatureSize, signatureSize);
		
		HelperFunctions.free_openssl_pointer((void *) signaturePointer);
		
		return signature;
	}

	public bool Verify(byte[] signature, byte[] data) => Public.Verify(signature, data);
}