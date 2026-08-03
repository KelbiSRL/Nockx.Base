namespace Nockx.Base.CryptographyTypes.MlKem;

public sealed class MlKemKey : AsymmetricKey {
	internal const string KeyType = "ML-KEM-768";

	private protected override string InstanceKeyType => KeyType;
	
	public new MlKemPublicKey Public => (MlKemPublicKey) base.Public;
	
	public MlKemKey() {
		
	}
	
	public static void GenerateKeyFile() {
		if (HelperFunctions.generate_key(KeyType) == 0)
			throw new InvalidOperationException("ML-KEM key file could not be generated");
	}

	public static MlKemKey ReadKeyFromFile(string fileName) {
		MlKemKey mlKemKey = HelperFunctions.ReadMlKemKeyFromFile(fileName);
		return mlKemKey.IsInvalid ? throw new InvalidOperationException("ML-KEM private key could not be read") : mlKemKey;
	}

	public byte[] EncryptRsaEncryptedAesKey(byte[] rsaEncryptedAesKey) => Public.EncryptRsaEncryptedAesKey(rsaEncryptedAesKey);
	
	public unsafe byte[] DecryptAesKey(byte[] data) { 
		uint singlyDecryptedAesKeyLength;
		IntPtr singlyDecryptedAesKeyPointer = MlKemCryptography.decrypt_aes_key_with_ml_kem(this, data, (uint) data.Length, &singlyDecryptedAesKeyLength);
		if (singlyDecryptedAesKeyPointer == IntPtr.Zero)
			throw new InvalidOperationException("AES key could not be decrypted with ML-KEM");

		byte[] singlyDecryptedAesKey = new byte[singlyDecryptedAesKeyLength];
		fixed (byte *singlyDecryptedAesKeyPtr = singlyDecryptedAesKey)
			Buffer.MemoryCopy((void *) singlyDecryptedAesKeyPointer, singlyDecryptedAesKeyPtr, singlyDecryptedAesKeyLength, singlyDecryptedAesKeyLength);
		
		HelperFunctions.free_openssl_pointer((void *) singlyDecryptedAesKeyPointer);
		
		return singlyDecryptedAesKey;
	}
}