using Nockx.Base.CryptographyTypes.Aes;
using Nockx.Base.CryptographyTypes.MlDsa;
using Nockx.Base.CryptographyTypes.MlKem;
using Nockx.Base.CryptographyTypes.Rsa;
using Nockx.Base.NockxKeyDataStorageTypes;

namespace Nockx.Base.CryptographyTypes;

public class NockxKey {
	public required RsaKey RsaKey { get; init; }
	public required MlKemKey MlKemKey { get; init; }
	public required MlDsaKey MlDsaKey { get; init; }
	
	public bool IsInvalid => RsaKey.IsInvalid || MlKemKey.IsInvalid || MlDsaKey.IsInvalid;
	
	public NockxPublicKey Public {
		get {
			if (field is not null)
				return field;

			field = new NockxPublicKey {
				RsaPublicKey = RsaKey.Public,
				MlKemPublicKey = MlKemKey.Public,
				MlDsaPublicKey = MlDsaKey.Public
			};
			
			return field;
		}
	}
	
	public static void GenerateCombinedKeyFile(string fileName = "private_key.pem") {
		if (File.Exists(fileName))
			throw new InvalidOperationException("Private key file already exists");
		
		// TODO: generate one key file in C++ instead. This is inefficient and insecure because it reads the private key from the file into memory
		MlKemKey.GenerateKeyFile();
		MlDsaKey.GenerateKeyFile();
		RsaKey.GenerateKeyFile();
		
		File.AppendAllText(fileName, File.ReadAllText($"{MlKemKey.KeyType.ToLowerInvariant()}_private_key.pem").Trim() + '\n');
		File.AppendAllText(fileName, File.ReadAllText($"{MlDsaKey.KeyType.ToLowerInvariant()}_private_key.pem").Trim() + '\n');
		File.AppendAllText(fileName, File.ReadAllText($"{RsaKey.KeyType.ToLowerInvariant()}_private_key.pem"));
		
		File.Delete($"{MlKemKey.KeyType.ToLowerInvariant()}_private_key.pem");
		File.Delete($"{MlDsaKey.KeyType.ToLowerInvariant()}_private_key.pem");
		File.Delete($"{RsaKey.KeyType.ToLowerInvariant()}_private_key.pem");
	}

	public static NockxKey ReadKeyFromFile(string fileName = "private_key.pem") => new () {
		RsaKey = RsaKey.ReadKeyFromFile(fileName),
		MlKemKey = MlKemKey.ReadKeyFromFile(fileName),
		MlDsaKey = MlDsaKey.ReadKeyFromFile(fileName)
	};
	
	public EncryptedKeyDataPair EncryptBytes(byte[] input, byte[]? additionalAuthenticationData = null) => Public.EncryptBytes(input, additionalAuthenticationData);
	
	public byte[] DecryptBytes(EncryptedKeyDataPair input, byte[]? additionalAuthenticationData = null) {
		byte[] singlyEncryptedAesKey = MlKemKey.DecryptAesKey(input.EncryptedAesKey);
		AesKey aesKey = RsaKey.DecryptAesKey(singlyEncryptedAesKey);

		return aesKey.Decrypt(input.EncryptedData, additionalAuthenticationData);
	}

	public CombinedSignature Sign(byte[] data) => new () {
		RsaSignature = RsaKey.Sign(data),
		MlDsaSignature = MlDsaKey.Sign(data)
	};
	
	public bool Verify(CombinedSignature signature, byte[] data) => Public.Verify(signature, data);
}