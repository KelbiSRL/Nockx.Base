using System.Runtime.InteropServices;

namespace Nockx.Base.CryptographyTypes.MlDsa;

public class MlDsaKey : SafeHandle {
	public override bool IsInvalid => handle == IntPtr.Zero;
	
	public unsafe byte[] Public {
		get {
			if (field is not null)
				return field;

			int publicKeySize;
			IntPtr publicKeyPointer = HelperFunctions.extract_public_key(handle, &publicKeySize);
			if (publicKeyPointer == IntPtr.Zero)
				throw new InvalidOperationException("ML-DSA public key could not be extracted");

			byte[] publicKey = new byte[publicKeySize];
			Marshal.Copy(publicKeyPointer, publicKey, 0, publicKeySize);
			HelperFunctions.free_pointer((void *) publicKeyPointer);

			field = publicKey;
			return field;
		}
	} = null;

	public MlDsaKey() : base(IntPtr.Zero, true) {
		
	}
	
	protected override bool ReleaseHandle() {
		HelperFunctions.destroy_asymmetric_key(handle);
		return true;
	}
}