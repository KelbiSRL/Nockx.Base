namespace Nockx.Base.CryptographyTypes.MlKem;

public class MlKemPublicKey : PublicKey {
	private protected override string InstanceKeyType => MlKemKey.KeyType;
	
	internal MlKemPublicKey(byte[] rawKey, byte? _) : base(rawKey, _) { }
	
	public MlKemPublicKey(byte[] rawKey) : base(rawKey) { }

	// TODO: decide whether iv should be in the returned byte array and if yes, whether to do it in C# or in C++
	public unsafe byte[] EncryptRsaEncryptedAesKey(byte[] rsaEncryptedAesKey, out byte[] iv) {
		uint encryptedAesKeyLength;
		iv = new byte[12];
		IntPtr encryptedAesKeyPointer = MlKemCryptography.encrypt_aes_key_with_ml_kem([..RawKey], (uint) RawKey.Length, iv, rsaEncryptedAesKey, (uint) rsaEncryptedAesKey.Length, &encryptedAesKeyLength);
		if (encryptedAesKeyPointer == IntPtr.Zero)
			throw new InvalidOperationException("AES key could not be encrypted with RSA");

		byte[] encryptedAesKey = new byte[encryptedAesKeyLength];
		fixed (byte *encryptedAesKeyPtr = encryptedAesKey)
			Buffer.MemoryCopy((void *) encryptedAesKeyPointer, encryptedAesKeyPtr, encryptedAesKeyLength, encryptedAesKeyLength);
		
		HelperFunctions.free_openssl_pointer((void *) encryptedAesKeyPointer);
		
		return encryptedAesKey;
	}
}