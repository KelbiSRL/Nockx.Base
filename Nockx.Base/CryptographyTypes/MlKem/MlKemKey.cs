namespace Nockx.Base.CryptographyTypes.MlKem;

public sealed class MlKemKey : AsymmetricKey {
	internal const string KeyType = "ML-KEM-768";

	internal override string InstanceKeyType => KeyType;
	
	public MlKemKey() {
		
	}
}