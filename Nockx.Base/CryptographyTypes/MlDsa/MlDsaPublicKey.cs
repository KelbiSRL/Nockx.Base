namespace Nockx.Base.CryptographyTypes.MlDsa;

public sealed class MlDsaPublicKey : PublicKey {
	private protected override string InstanceKeyType => MlDsaKey.KeyType;
	
	internal MlDsaPublicKey(byte[] rawKey, byte? _) : base(rawKey, _) { }
	
	public MlDsaPublicKey(byte[] rawKey) : base(rawKey) { }
	
	public bool Verify(byte[] signature, byte[] data) {
		int result = MlDsaCryptography.verify_with_ml_dsa([..RawKey], RawKey.Length, data, (ulong) data.LongLength, signature, (uint) signature.Length);
		if (result == -1)
			throw new InvalidOperationException("Data could not be verified");

		return result != 0;
	}
}