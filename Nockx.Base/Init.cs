using System.Runtime.InteropServices;

namespace Nockx.Base;

internal static partial class Init {
	[LibraryImport("libnockx-base")]
	private static unsafe partial void init_secure_heap();
	
	internal static void InitSecureHeap() => init_secure_heap();
}