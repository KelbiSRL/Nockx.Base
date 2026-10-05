using System.Collections.Immutable;

namespace Nockx.Base.CryptographyTypes;

public abstract class PublicKey {
	private protected abstract string InstanceKeyType { get; }
	
	public readonly ImmutableArray<byte> RawKey;

	private protected PublicKey(byte[] rawKey, byte? _) {
		RawKey = [..rawKey];
	}
	
	protected PublicKey(byte[] rawKey) {
		string keyType = Cryptography.GetKeyType(rawKey);
		if (keyType != InstanceKeyType)
			throw new InvalidOperationException($"Public {InstanceKeyType} key was attempted to be created with {keyType} key data");
		
		RawKey = [..rawKey];
	}

	public override string ToString() => Convert.ToBase64String([..RawKey]);
}