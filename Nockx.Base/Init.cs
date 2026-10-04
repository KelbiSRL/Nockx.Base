using System.Runtime.InteropServices;

namespace Nockx.Base;

internal static partial class Init {
	[LibraryImport("libnockx-base")]
	internal static partial void init_secure_heap(ulong size, ulong minSize);
}