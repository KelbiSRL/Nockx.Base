using Nockx.Base.CryptographyTypes.Aes;
using Nockx.Base.CryptographyTypes.MlDsa;
using Nockx.Base.CryptographyTypes.MlKem;
using Nockx.Base.CryptographyTypes.Rsa;
using Nockx.Base.NockxKeyDataStorageTypes;

namespace Nockx.Base.CryptographyTypes;

public class NockxPublicKey {
	public required RsaPublicKey RsaPublicKey { get; init; }
	public required MlKemPublicKey MlKemPublicKey { get; init; }
	public required MlDsaPublicKey MlDsaPublicKey { get; init; }
	
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
}