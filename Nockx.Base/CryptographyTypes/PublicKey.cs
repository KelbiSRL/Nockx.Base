using System.Collections.Immutable;
using Nockx.Base.CryptographyTypes.MlDsa;
using Nockx.Base.CryptographyTypes.MlKem;
using Nockx.Base.CryptographyTypes.Rsa;

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

	public static implicit operator PublicKey(string key) {
        ArgumentNullException.ThrowIfNull(key);

        string keyType = Cryptography.GetKeyType(Convert.FromBase64String(key));

		return keyType switch {
			RsaKey.KeyType => new RsaPublicKey(key),
			MlKemKey.KeyType => new MlKemPublicKey(key),
			MlDsaKey.KeyType => new MlDsaPublicKey(key),
			_ => throw new ArgumentException("Unsupported key type", nameof(key))
		};
	}

	public static bool operator ==(PublicKey? a, PublicKey? b) => a?.Equals(b) ?? b is null;

	public static bool operator !=(PublicKey? a, PublicKey? b) => !(a == b);

	public bool Equals(PublicKey? other) => other is not null && ToString() == other.ToString();

	public override bool Equals(object? obj) => obj is PublicKey key && Equals(key);

	public override int GetHashCode() => ToString().GetHashCode();

	public override string ToString() => Convert.ToBase64String([..RawKey]).Trim();
}