namespace Nockx.Base.CryptographyTypes.MlKem;

public class MlKemPublicKey : PublicKey {
	private protected override string InstanceKeyType => MlKemKey.KeyType;
	
	internal MlKemPublicKey(byte[] rawKey, byte? _) : base(rawKey, _) { }
	
	public MlKemPublicKey(byte[] rawKey) : base(rawKey) { }

	public unsafe byte[] EncryptRsaEncryptedAesKey(byte[] rsaEncryptedAesKey) {
		uint encryptedAesKeyLength;
		IntPtr encryptedAesKeyPointer = MlKemCryptography.encrypt_aes_key_with_ml_kem([..RawKey], (uint) RawKey.Length, rsaEncryptedAesKey, (uint) rsaEncryptedAesKey.Length, &encryptedAesKeyLength);
		if (encryptedAesKeyPointer == IntPtr.Zero)
			throw new InvalidOperationException("AES key could not be encrypted with RSA");

		byte[] encryptedAesKey = new byte[encryptedAesKeyLength];
		fixed (byte *encryptedAesKeyPtr = encryptedAesKey)
			Buffer.MemoryCopy((void *) encryptedAesKeyPointer, encryptedAesKeyPtr, encryptedAesKeyLength, encryptedAesKeyLength);
		
		HelperFunctions.free_openssl_pointer((void *) encryptedAesKeyPointer);
		
		return encryptedAesKey;
	}
}