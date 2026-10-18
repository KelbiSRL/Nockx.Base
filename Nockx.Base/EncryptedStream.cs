using System.Security.Cryptography;
using Nockx.Base.CryptographyTypes.Aes;

namespace Nockx.Base;

public class EncryptedStream : Stream {
	private readonly AesGcmStreamContext _context;
	private readonly Stream _underlyingStream;
	private readonly bool _leaveUnderlyingStreamOpen;
	
	private bool _isDisposed;
	
	public readonly byte[] Iv;
	
	public unsafe EncryptedStream(Stream underlyingStream, AesKey aesKey, bool forEncryption, byte[]? iv = null, byte[]? aad = null, bool leaveUnderlyingStreamOpen = false) {
		if (!forEncryption && iv is null)
			throw new ArgumentNullException(nameof(iv), "IV must be specified when decrypting");

		if (iv is null) {
			Iv = new byte[AesKey.IvLength];

			fixed (byte *ivPtr = Iv)
				if (AesCryptography.generate_iv(ivPtr) != 1)
					throw new InvalidOperationException("IV could not be generated");
		} else {
			Iv = iv;
		}

		_leaveUnderlyingStreamOpen = leaveUnderlyingStreamOpen;
		
		_context = AesGcmStreamContext.Generate(forEncryption, aesKey, Iv, aad ?? []);
		_underlyingStream = underlyingStream;
	}

	public override void Flush() => _underlyingStream.Flush();

	public unsafe byte[] CalculateTag() {
		if (!_context.ForEncryption)
			throw new InvalidOperationException("Tried to calculate tag for decryption stream");

		byte[] tag = new byte[AesKey.TagLength];
		fixed (byte *tagPtr = tag)
			return AesCryptography.gcm_stream_final(_context, 1, tagPtr) != -1 ? tag : throw new CryptographicException("Calculating tag failed");
	}

	public unsafe bool VerifyTag(byte[] tag) {
		if (_context.ForEncryption)
			throw new InvalidOperationException("Tried to calculate tag for encryption stream");

		sbyte returnVal;
		fixed (byte *tagPtr = tag)
			returnVal = AesCryptography.gcm_stream_final(_context, 0, tagPtr);
		
		return returnVal == -1 ? throw new CryptographicException("Verifying tag failed") : returnVal != 0;
	}
	
	public override unsafe int Read(byte[] buffer, int offset, int count) {
		byte[] underlyingBuffer = new byte[count];
		int read = _underlyingStream.Read(underlyingBuffer, 0, count);
		fixed (byte *underlyingBufferPtr = underlyingBuffer) {
			fixed (byte *bufferPtr = buffer) {
				int finalRead = AesCryptography.gcm_stream_update(_context, underlyingBufferPtr, read, bufferPtr + offset);
				return finalRead < 0 ? throw new CryptographicException() : finalRead;
			}
		}
	}
	
	/**
	 * Reads <c>amount</c> bytes, encrypts and then discards them. This method is used to continue an interrupted read with identical data.
	 */
	public unsafe void ReadAndDiscard(long amount) {
		if (amount > Length)
			throw new ArgumentOutOfRangeException(nameof(amount), "The amount of bytes to be read cannot be larger than the stream length");
		
		long left = amount;
		while (left > 0) {
			byte[] underlyingBuffer = new byte[Math.Min(1024, left)];
			int read = _underlyingStream.Read(underlyingBuffer, 0, underlyingBuffer.Length);
			byte[] discardedBuffer = new byte[read];
			fixed (byte *underlyingBufferPtr = underlyingBuffer)
				fixed (byte *discardedBufferPtr = discardedBuffer)
					left -= AesCryptography.gcm_stream_update(_context, underlyingBufferPtr, read, discardedBufferPtr);
		}
	}
		
	public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException("Tried to seek in a forward-only stream");
		
	public override void SetLength(long value) => _underlyingStream.SetLength(value);
	
	public override unsafe void Write(byte[] buffer, int offset, int count) {
		byte[] outputBuffer = new byte[count];

		fixed (byte *outputBufferPtr = outputBuffer) {
			fixed (byte *bufferPtr = buffer) {
				int read = AesCryptography.gcm_stream_update(_context, bufferPtr + offset, count, outputBufferPtr);
				if (read < 0)
					throw new CryptographicException();

				_underlyingStream.Write(outputBuffer, 0, read);
			}
		}
	}

	public override bool CanRead => _underlyingStream.CanRead;
	public override bool CanSeek => false;
	public override bool CanWrite => _underlyingStream.CanWrite;
	public override long Length => _underlyingStream.Length;

	public override long Position {
		get => _underlyingStream.Position;
		set => throw new NotSupportedException("Tried to set position of a forward-only stream");
	}
	
	protected override void Dispose(bool disposing) {
		if (!_isDisposed) {
			_isDisposed = true;
			
			_context.Dispose();
			
			if (disposing && !_leaveUnderlyingStreamOpen)
				_underlyingStream.Dispose();
		}
		
		base.Dispose(disposing);
	}
}