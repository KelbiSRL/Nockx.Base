using System.Runtime.InteropServices;

namespace Nockx.Base;

internal static partial class Init {
	[LibraryImport("libnockx-base")]
	internal static unsafe partial void init_secure_heap();
}