using System.Runtime.InteropServices;

namespace Nockx.Base.Util;

internal static class SafeHandleExtension {
	public static IntPtr AddRefAndGetPointer(this SafeHandle safeHandle) {
		bool success = false;
		safeHandle.DangerousAddRef(ref success);
		if (!success)
			throw new InvalidOperationException();

		return safeHandle.DangerousGetHandle();
	}
}