using System.Runtime.InteropServices;
using Nockx.Base.CryptographyTypes.MlDsa;
using Nockx.Base.CryptographyTypes.MlKem;
using Nockx.Base.CryptographyTypes.Rsa;

namespace Nockx.Base.CryptographyTypes;

public abstract class AsymmetricKey() : SafeHandle(IntPtr.Zero, true) {
	private protected abstract string InstanceKeyType { get; }
	
	public sealed override bool IsInvalid => handle == IntPtr.Zero;
	
	public unsafe PublicKey Public {
		get {
			if (field is not null)
				return field;

			int publicKeySize;
			IntPtr publicKeyPointer = HelperFunctions.extract_public_key(this, &publicKeySize);
			if (publicKeyPointer == IntPtr.Zero)
				throw new InvalidOperationException($"{InstanceKeyType} public key could not be extracted");

			byte[] publicKey = new byte[publicKeySize];
			Marshal.Copy(publicKeyPointer, publicKey, 0, publicKeySize);
			HelperFunctions.free_pointer((void *) publicKeyPointer);

			field = InstanceKeyType switch {
				RsaKey.KeyType => new RsaPublicKey(publicKey, null),
				MlKemKey.KeyType => new MlKemPublicKey(publicKey, null),
				MlDsaKey.KeyType => new MlDsaPublicKey(publicKey, null),
				_ => throw new InvalidOperationException($"{InstanceKeyType} key type is not supported")
			};
			return field;
		}
	} = null;
	
	protected sealed override bool ReleaseHandle() {
		HelperFunctions.destroy_asymmetric_key(handle);
		return true;
	}
}