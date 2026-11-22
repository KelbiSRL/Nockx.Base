namespace Nockx.Base.CryptographyTypes.MlKem;

public class MlKemPublicKey : PublicKey {
	private protected override string InstanceKeyType => MlKemKey.KeyType;
	
	internal MlKemPublicKey(byte[] rawKey, byte? _) : base(rawKey, _) { }
	
	public MlKemPublicKey(byte[] rawKey) : base(rawKey) { }
	
	public MlKemPublicKey(string key) : base(Convert.FromBase64String(key)) { }
	
	public static implicit operator MlKemPublicKey(string keyString) => new (keyString);

	public unsafe byte[] EncryptRsaEncryptedAesKey(byte[] rsaEncryptedAesKey) {
		uint encryptedAesKeyLength;
		IntPtr encryptedAesKeyPointer = MlKemCryptography.encrypt_aes_key_with_ml_kem([..RawKey], (uint) RawKey.Length, rsaEncryptedAesKey, (uint) rsaEncryptedAesKey.Length, &encryptedAesKeyLength);
		if (encryptedAesKeyPointer == IntPtr.Zero)
			throw new InvalidOperationException("AES key could not be encrypted with RSA");

		try {
			byte[] encryptedAesKey = new byte[encryptedAesKeyLength];
			fixed (byte *encryptedAesKeyPtr = encryptedAesKey)
				Buffer.MemoryCopy((void *) encryptedAesKeyPointer, encryptedAesKeyPtr, encryptedAesKeyLength, encryptedAesKeyLength);

			return encryptedAesKey;
		} finally {
			HelperFunctions.free_openssl_pointer((void *) encryptedAesKeyPointer, encryptedAesKeyLength);
		}
	}
}