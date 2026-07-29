using Nockx.Base.CryptographyTypes.Aes;

namespace Nockx.Base.CryptographyTypes.Rsa;

public sealed class RsaKey : AsymmetricKey {
	internal const string KeyType = "RSA";
	
	internal override string InstanceKeyType => KeyType;

	public RsaKey() {
		
	}

	public static void GenerateKeyFile() {
		if (HelperFunctions.generate_key(KeyType) == 0)
			throw new InvalidOperationException("RSA key file could not be generated");
	}

	public static RsaKey ReadKeyFromFile(string fileName) {
		RsaKey rsaKey = HelperFunctions.read_key_from_file(fileName, KeyType);
		return rsaKey.IsInvalid ? throw new InvalidOperationException("RSA private key could not be read") : rsaKey;
	}

	public unsafe byte[] EncryptAesKey(AesKey aesKey) {
		uint encryptedAesKeyLength;
		IntPtr encryptedAesKeyPointer = RsaCryptography.encrypt_aes_key_with_rsa(Public, (uint) Public.Length, aesKey, &encryptedAesKeyLength);
		if (encryptedAesKeyPointer == IntPtr.Zero)
			throw new InvalidOperationException($"AES key could not be encrypted with RSA");

		byte[] encryptedAesKey = new byte[encryptedAesKeyLength];
		fixed (byte *encryptedAesKeyPtr = encryptedAesKey)
			Buffer.MemoryCopy((void *) encryptedAesKeyPointer, encryptedAesKeyPtr, encryptedAesKeyLength, encryptedAesKeyLength);
		
		HelperFunctions.free_openssl_pointer((void *) encryptedAesKeyPointer);
		
		return encryptedAesKey;
	}
}