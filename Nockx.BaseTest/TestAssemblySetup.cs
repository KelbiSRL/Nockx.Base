using System.Runtime.CompilerServices;
using Nockx.Base;

namespace Nockx.BaseTest;

public static class TestAssemblySetup {
	[ModuleInitializer]
	public static void Initialize() => Cryptography.InitSecureHeap();
}