namespace Nockx.Base.NockxKeyDataStorageTypes;

public class CombinedSignature {
	public required byte[] RsaSignature, MlDsaSignature;
}