using Nockx.Base.CryptographyTypes.Aes;
using Nockx.Base.CryptographyTypes.MlDsa;
using Nockx.Base.CryptographyTypes.MlKem;
using Nockx.Base.CryptographyTypes.Rsa;
using Nockx.Base.NockxKeyDataStorageTypes;

namespace Nockx.Base.CryptographyTypes;

public class NockxPublicKey {
	public RsaPublicKey RsaPublicKey { get; }
	public MlKemPublicKey MlKemPublicKey { get; }
	public MlDsaPublicKey MlDsaPublicKey { get; }

	public NockxPublicKey(RsaPublicKey rsaPublicKey, MlKemPublicKey mlKemPublicKey, MlDsaPublicKey mlDsaPublicKey) {
		RsaPublicKey = rsaPublicKey;
		MlKemPublicKey = mlKemPublicKey;
		MlDsaPublicKey = mlDsaPublicKey;
	}
	
	public NockxPublicKey(string keyString) {
		byte[][] keys = [..keyString.Split(':').Select(Convert.FromBase64String)];
		if (keys.Length != 3)
			throw new IndexOutOfRangeException($"A {keys.Length}-part key was passed (expected 3 parts)");
		
		RsaPublicKey = new RsaPublicKey(keys[0]);
		MlKemPublicKey = new MlKemPublicKey(keys[1]);
		MlDsaPublicKey = new MlDsaPublicKey(keys[2]);
	}
	
	public EncryptedKeyDataPair EncryptBytes(byte[] input, byte[]? additionalAuthenticationData = null) {
		using AesKey aesKey = AesKey.Generate();
	
		byte[] cipherBytes = aesKey.Encrypt(input, additionalAuthenticationData);
		byte[] doublyEncryptedAesKey = EncryptAesKey(aesKey);
	
		return new EncryptedKeyDataPair {
			EncryptedAesKey = doublyEncryptedAesKey,
			EncryptedData = cipherBytes
		};
	}

	public byte[] EncryptAesKey(AesKey aesKey) {
		byte[] rsaEncryptedAesKey = RsaPublicKey.EncryptAesKey(aesKey);
		return MlKemPublicKey.EncryptRsaEncryptedAesKey(rsaEncryptedAesKey);
	}
	
	public bool Verify(CombinedSignature signature, byte[] data, AesKey[]? aesKeys = null) => RsaPublicKey.Verify(signature.RsaSignature, data, aesKeys) && MlDsaPublicKey.Verify(signature.MlDsaSignature, data, aesKeys);

	public static implicit operator NockxPublicKey(string keyString) => new (keyString);
	
	public static bool operator ==(NockxPublicKey? a, NockxPublicKey? b) => a?.Equals(b) ?? b is null;
	
	public static bool operator !=(NockxPublicKey? a, NockxPublicKey? b) => !(a == b);
	
	public bool Equals(NockxPublicKey? other) => other is not null && ToString() == other.ToString();

	public override bool Equals(object? obj) => obj is NockxPublicKey key && Equals(key);

	public override int GetHashCode() => ToString().GetHashCode();

	public override string ToString() => $"{RsaPublicKey}:{MlKemPublicKey}:{MlDsaPublicKey}";
}