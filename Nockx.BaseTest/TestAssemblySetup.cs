using System.Runtime.CompilerServices;
using Nockx.Base;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Nockx.BaseTest;

public static class TestAssemblySetup {
	[ModuleInitializer]
	public static void Initialize() => Cryptography.InitSecureHeap();
}