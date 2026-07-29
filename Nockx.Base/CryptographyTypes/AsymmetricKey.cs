using System.Runtime.InteropServices;

namespace Nockx.Base.CryptographyTypes;

public abstract class AsymmetricKey() : SafeHandle(IntPtr.Zero, true) {
	internal abstract string InstanceKeyType { get; }
	
	public sealed override bool IsInvalid => handle == IntPtr.Zero;
	
	public unsafe byte[] Public {
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

			field = publicKey;
			return field;
		}
	} = null;
	
	protected sealed override bool ReleaseHandle() {
		HelperFunctions.destroy_asymmetric_key(handle);
		return true;
	}
}