using System.Runtime.InteropServices;

namespace Nockx.Base.Util;

public sealed class IntPtrConversionScope : IDisposable {
	private readonly IReadOnlyList<SafeHandle> _safeHandles;
	private int _amountAdded;
	public IntPtr[] Pointers { get; }
	
	public IntPtrConversionScope(IReadOnlyList<SafeHandle> safeHandles) {
		_safeHandles = safeHandles;
		Pointers = new IntPtr[safeHandles.Count];

		try {
			for (; _amountAdded < safeHandles.Count; _amountAdded++)
				Pointers[_amountAdded] = safeHandles[_amountAdded].AddRefAndGetPointer();
		} catch {
			Dispose();
			throw;
		}
	}

	public void Dispose() {
		for (int i = 0; i < _amountAdded; i++)
			_safeHandles[i].DangerousRelease();

		_amountAdded = 0;
	}
}