using Nockx.Base.CryptographyTypes.Aes;
using Nockx.Base.Util;

namespace Nockx.Base.CryptographyTypes.MlDsa;

public sealed class MlDsaPublicKey : PublicKey {
	private protected override string InstanceKeyType => MlDsaKey.KeyType;
	
	internal MlDsaPublicKey(byte[] rawKey, byte? _) : base(rawKey, _) { }
	
	public MlDsaPublicKey(byte[] rawKey) : base(rawKey) { }
	
	public MlDsaPublicKey(string key) : base(Convert.FromBase64String(key)) { }
	
	public static implicit operator MlDsaPublicKey(string keyString) => new (keyString);
	
	public bool Verify(byte[] signature, byte[] data, AesKey[]? aesKeys = null) {
		aesKeys ??= [];
		
		using IntPtrConversionScope scope = new (aesKeys);
		int result = MlDsaCryptography.verify_with_ml_dsa([..RawKey], RawKey.Length, data, (ulong) data.LongLength, scope.Pointers, scope.Pointers.Length, signature, (uint) signature.Length);
		if (result == -1)
			throw new InvalidOperationException("Data could not be verified");

		return result != 0;
	}
}