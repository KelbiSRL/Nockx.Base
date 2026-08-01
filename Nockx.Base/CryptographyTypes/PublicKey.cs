using System.Collections.Immutable;

namespace Nockx.Base.CryptographyTypes;

public abstract class PublicKey {
	private protected abstract string InstanceKeyType { get; }
	
	public readonly ImmutableArray<byte> RawKey;

	// TODO: the private protected one should not have a check whether the key is a valid key matching its type (for efficiency reasons), while the protected one should (so the user doesn't receive an error down the line and wonder where it comes from)
	private protected PublicKey(byte[] rawKey, byte? _) {
		RawKey = [..rawKey];
	}
	
	protected PublicKey(byte[] rawKey) {
		RawKey = [..rawKey];
	}
}