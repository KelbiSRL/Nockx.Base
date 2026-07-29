using Nockx.Base.CryptographyTypes.MlDsa;
using Nockx.Base.CryptographyTypes.MlKem;
using Nockx.Base.CryptographyTypes.Rsa;

namespace Nockx.Base.CryptographyTypes;

public class NockxKey {
	public required RsaKey RsaKey { get; init; }
	public required MlKemKey MlKemKey { get; init; }
	public required MlDsaKey MlDsaKey { get; init; }
}