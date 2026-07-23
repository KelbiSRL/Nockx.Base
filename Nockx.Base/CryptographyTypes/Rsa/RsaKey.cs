using System.Runtime.InteropServices;

namespace Nockx.Base.CryptographyTypes.Rsa;

public sealed class RsaKey() : SafeHandle(IntPtr.Zero, true) {
	public override bool IsInvalid => handle == IntPtr.Zero;

	public unsafe byte[] Public {
		get {
			if (field is not null)
				return field;

			int publicKeySize;
			IntPtr publicKeyPointer = HelperFunctions.extract_public_key(handle, &publicKeySize);
			if (publicKeyPointer == IntPtr.Zero)
				throw new InvalidOperationException("RSA public key could not be extracted");

			byte[] publicKey = new byte[publicKeySize];
			Marshal.Copy(publicKeyPointer, publicKey, 0, publicKeySize);
			HelperFunctions.free_pointer((void *) publicKeyPointer);

			field = publicKey;
			return field;
		}
	} = null;
	
	protected override bool ReleaseHandle() {
		HelperFunctions.destroy_asymmetric_key(handle);
		return true;
	}
}