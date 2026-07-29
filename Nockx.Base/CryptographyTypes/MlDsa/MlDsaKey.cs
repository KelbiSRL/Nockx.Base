namespace Nockx.Base.CryptographyTypes.MlDsa;

public sealed class MlDsaKey : AsymmetricKey {
	internal const string KeyType = "ML-DSA-65";

	internal override string InstanceKeyType => KeyType;

	public MlDsaKey() {
		
	}
}