using System.Runtime.InteropServices;

namespace Nockx.Base.CryptographyTypes.Aes;

public class AesGcmStreamContext : SafeHandle {
	public override bool IsInvalid => handle == IntPtr.Zero;
	
	/**
	 * Creating an instance of <see cref="AesGcmStreamContext"/> does not yield a valid instance. Use <see cref="Generate">AesGcmStreamContext.Generate</see>
	 */
	public AesGcmStreamContext() : base(IntPtr.Zero, true) { }
	
	public static AesGcmStreamContext Generate(bool forEncryption, AesKey aesKey, byte[] iv, byte[] aad) {
		AesGcmStreamContext stream = AesCryptography.create_gcm_context_for_stream(forEncryption ? (byte) 1 : (byte) 0, aesKey, iv, aad, (ulong) aad.LongLength);
		return stream.IsInvalid ? throw new InvalidOperationException($"{nameof(AesGcmStreamContext)} could not be created") : stream;
	}

	protected sealed override bool ReleaseHandle() {
		AesCryptography.gcm_stream_dispose(handle);
		return true;
	}
}