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
		AesKey aesKey = AesKey.Generate();
	
		byte[] cipherBytes = aesKey.Encrypt(input, additionalAuthenticationData);
		byte[] rsaEncryptedAesKey = RsaPublicKey.EncryptAesKey(aesKey);
		byte[] doublyEncryptedAesKey = MlKemPublicKey.EncryptRsaEncryptedAesKey(rsaEncryptedAesKey);
	
		return new EncryptedKeyDataPair {
			EncryptedAesKey = doublyEncryptedAesKey,
			EncryptedData = cipherBytes
		};
	}
	
	public bool Verify(CombinedSignature signature, byte[] data) => RsaPublicKey.Verify(signature.RsaSignature, data) && MlDsaPublicKey.Verify(signature.MlDsaSignature, data);

	public override string ToString() => $"{RsaPublicKey}:{MlKemPublicKey}:{MlDsaPublicKey}";
}