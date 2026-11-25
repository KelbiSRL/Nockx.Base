using Nockx.Base.CryptographyTypes.Aes;
using Nockx.Base.Util;

namespace Nockx.Base.CryptographyTypes.Rsa;

public sealed class RsaPublicKey : PublicKey {
	private protected override string InstanceKeyType => RsaKey.KeyType;
	
	internal RsaPublicKey(byte[] key, byte? _) : base(key, _) { }

	public RsaPublicKey(byte[] key) : base(key) { }
	
	public RsaPublicKey(string key) : base(Convert.FromBase64String(key)) { }
	
	public static implicit operator RsaPublicKey(string keyString) => new (keyString);
	
	public unsafe byte[] EncryptAesKey(AesKey aesKey) {
		uint encryptedAesKeyLength;
		IntPtr encryptedAesKeyPointer = RsaCryptography.encrypt_aes_key_with_rsa([..RawKey], (uint) RawKey.Length, aesKey, &encryptedAesKeyLength);
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

	public bool Verify(byte[] signature, byte[] data, AesKey[]? aesKeys = null) {
		aesKeys ??= [];
		
		using IntPtrConversionScope scope = new (aesKeys);
		int result = RsaCryptography.verify_with_rsa([..RawKey], RawKey.Length, data, (ulong) data.LongLength, scope.Pointers, scope.Pointers.Length, signature, (uint) signature.Length);
		if (result == -1)
			throw new InvalidOperationException("Data could not be verified");

		return result != 0;
	}
}