namespace Nockx.Base.CryptographyTypes.MlDsa;

public sealed class MlDsaKey : AsymmetricKey {
	internal const string KeyType = "ML-DSA-65";

	private protected override string InstanceKeyType => KeyType;

	public new MlDsaPublicKey Public => (MlDsaPublicKey) base.Public;
	
	public MlDsaKey() {
		
	}
	
	public static void GenerateKeyFile() {
		if (HelperFunctions.generate_key(KeyType) == 0)
			throw new InvalidOperationException("ML-DSA key file could not be generated");
	}

	public static MlDsaKey ReadKeyFromFile(string fileName) {
		MlDsaKey mlDsaKey = HelperFunctions.ReadMlDsaKeyFromFile(fileName);
		return mlDsaKey.IsInvalid ? throw new InvalidOperationException("ML-DSA private key could not be read") : mlDsaKey;
	}
	
	public unsafe byte[] Sign(byte[] data) {
		ulong signatureSize;
		IntPtr signaturePointer = MlDsaCryptography.sign_with_ml_dsa(this, data, (ulong) data.LongLength, &signatureSize);
		if (signaturePointer == IntPtr.Zero)
			throw new InvalidOperationException("Data could not be signed with ML-DSA");

		byte[] signature = new byte[signatureSize];
		fixed (byte *signaturePtr = signature)
			Buffer.MemoryCopy((void *) signaturePointer, signaturePtr, signatureSize, signatureSize);
		
		HelperFunctions.free_openssl_pointer((void *) signaturePointer);
		
		return signature;
	}

	public bool Verify(byte[] signature, byte[] data) => Public.Verify(signature, data);
}