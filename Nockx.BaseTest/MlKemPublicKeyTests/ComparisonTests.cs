using Nockx.Base.CryptographyTypes.MlKem;

namespace Nockx.BaseTest.MlKemPublicKeyTests;

public class ComparisonTests {
	[Fact]
	public void KeysEqual() {
		using MlKemKey key1 = MlKemKey.ReadKeyFromFile("nockxtestkey.pem");
		using MlKemKey key2 = MlKemKey.ReadKeyFromFile("nockxtestkey.pem");
		
		Assert.True(key1.Public == key2.Public);
		Assert.False(key1.Public != key2.Public);
		Assert.Equal(key1.Public, key2.Public);
	}
	
	[Fact]
	public void KeysNotEqual() {
		using MlKemKey key1 = MlKemKey.ReadKeyFromFile("nockxtestkey.pem");
		using MlKemKey key2 = MlKemKey.ReadKeyFromFile("nockxtestkey2.pem");
		
		Assert.True(key1.Public != key2.Public);
		Assert.False(key1.Public == key2.Public);
		Assert.NotEqual(key1.Public, key2.Public);
	}

	[Fact]
	public void KeyEqualString() {
		using MlKemKey key = MlKemKey.ReadKeyFromFile("nockxtestkey.pem");
		const string keyString = "MIIEsjALBglghkgBZQMEBAIDggShACSGZxsomrP8bhvktZZBkQ9pQSpFagPCyz/LsDQ2PXwMu/W0XgQSBqbYKlh1KF6QCUWyjsCilR67cQUHv9elYoeIlmWkgYZVx27pBrfJfea0yw1BepAYx2spAFEjG/OxUw+bJYDQAJO7bRTwQnngElmckiORiGRKQFGbzhJgXUBnlRIgBf/iNnVWfAPQt2Z3sr4kJP/MLoRLuZNpgSaTtUHqKhTYTaQEKVDDLBBsCoeovcZoURpkB9iMSLARaJjWRFurv4JqIiOqVtpwHTXpO+HziDRYbC4cdSK0YixpEGNIQ03wP0ZijZHQxtSGXRZ0DXNVc8CboMZ1j5j4zj94piMLh+ZoYeURnTI4fNfRwDHYlYIEyLo6wDC0sN6MP+XlCen6tGtlqvH6CX5JpqwCs8YqJbjjqN01TuvnsO2gDYSTP0rTY1+WQKNslb/3Zpo3oSDnxA8jF8XLMGrqNguwpmiGwfHoYm+cM0WKv2Lazegbl8eQN8lTZGrbErPDQWOrYL4GuYNWYRMUwrNMnX5XfdXpqIrMOT7DwPQHviZbsdOQjwe6FiU1g1hAAferiNiLIeWzdWbSbg7DaPvcw5EwNvocKJnmZ0Ahnk1ok+OFSqbKTeZsNWwQFEvppdnxWxkTXgssvd8xyFKMZTmorwxRwhr5G8bsHQk2IknIxrCWnm7jNz1rFUJjP/WaUgmUTQpDeqKrl0IEdnVXm6i6iO7HNpcJuf8nebbiwEFroZk1X3T3MLeQlwbqQOv6Ug8qq3IpBL8MOYhjGo1ls9P1no14NUeYg1D3HF2ydypjIHScCCTHO/P2wAOwlCbnxKpBIJILG0wpZDQmt0QHDjtptm8Fpfabw4/AL1XnmKqTD8eLA1Jmq6BmYScpMXA6LR5re3kVja7TfC6yEyEslYvwaTz3gGWaYAUCrXzCz7GoSzO7mgFodVjSujPshOv1s9eDm5E6Gdz2B5iJy88RjEu7saB7plEkh2GVL0kxhwcXuAnASUVYldRizr63hhJCTi9XWXEDVIORPl+sJEqSctiUHsRokSRFfZUswLXAJuaTaJKLa2k8V4yKGdlSnq6kwlgwv6lXfzh4WgfbazlFRkYsiPpmi3v3FrSTSxfDeDe6OCfADxM6Gocifp/EzL+kLEb6bQT8EuKZYmTCqGKStg5rXZjVVlz1oj7RUx3SFSNbXh/TpvaZUwFQbIqzGMTEKGCypi9WtuBZShQXkpe7m9AWzBAsdSlkFQj4LlVLo+ngnwIacFd6Tw/MlNj7HJvBQgtgIr1BCYV3KrAcMCMRW21WPxgQBMZJPiK7tUF4LCfjEKoqLq/VcuxrFetFTaeZUJWDYtTgLVzmEUJyOH3pNszmsC1mwHP6UAlCgTP4bSglWacSnmByw4/FgElyuN3Iv17JNWOBFh6SMkuQltu7VWuUi/T5rDnRoMF5Y027QIQzSrxIUvBcJOjBlk3onX3SjGqagTuRbdXoDMV3toWVBjMcxARCt4waplfDsyi3Rmc0o5tGBGVaZxV5rRWFG/AFCjnwQv26ZcGk8JZdMr3GJBVIJGP8NxV4gysXDvkiZhYiJSFeDuSt";
		
		Assert.True(key.Public == keyString);
		Assert.True(keyString == key.Public);
		Assert.False(key.Public != keyString);
		Assert.False(keyString != key.Public);
		Assert.Equal(key.Public, keyString);
		Assert.Equal(keyString, key.Public);
	}
	
	[Fact]
	public void KeyNotEqualString() {
		using MlKemKey key = MlKemKey.ReadKeyFromFile("nockxtestkey2.pem");
		const string keyString = "MIIEsjALBglghkgBZQMEBAIDggShACSGZxsomrP8bhvktZZBkQ9pQSpFagPCyz/LsDQ2PXwMu/W0XgQSBqbYKlh1KF6QCUWyjsCilR67cQUHv9elYoeIlmWkgYZVx27pBrfJfea0yw1BepAYx2spAFEjG/OxUw+bJYDQAJO7bRTwQnngElmckiORiGRKQFGbzhJgXUBnlRIgBf/iNnVWfAPQt2Z3sr4kJP/MLoRLuZNpgSaTtUHqKhTYTaQEKVDDLBBsCoeovcZoURpkB9iMSLARaJjWRFurv4JqIiOqVtpwHTXpO+HziDRYbC4cdSK0YixpEGNIQ03wP0ZijZHQxtSGXRZ0DXNVc8CboMZ1j5j4zj94piMLh+ZoYeURnTI4fNfRwDHYlYIEyLo6wDC0sN6MP+XlCen6tGtlqvH6CX5JpqwCs8YqJbjjqN01TuvnsO2gDYSTP0rTY1+WQKNslb/3Zpo3oSDnxA8jF8XLMGrqNguwpmiGwfHoYm+cM0WKv2Lazegbl8eQN8lTZGrbErPDQWOrYL4GuYNWYRMUwrNMnX5XfdXpqIrMOT7DwPQHviZbsdOQjwe6FiU1g1hAAferiNiLIeWzdWbSbg7DaPvcw5EwNvocKJnmZ0Ahnk1ok+OFSqbKTeZsNWwQFEvppdnxWxkTXgssvd8xyFKMZTmorwxRwhr5G8bsHQk2IknIxrCWnm7jNz1rFUJjP/WaUgmUTQpDeqKrl0IEdnVXm6i6iO7HNpcJuf8nebbiwEFroZk1X3T3MLeQlwbqQOv6Ug8qq3IpBL8MOYhjGo1ls9P1no14NUeYg1D3HF2ydypjIHScCCTHO/P2wAOwlCbnxKpBIJILG0wpZDQmt0QHDjtptm8Fpfabw4/AL1XnmKqTD8eLA1Jmq6BmYScpMXA6LR5re3kVja7TfC6yEyEslYvwaTz3gGWaYAUCrXzCz7GoSzO7mgFodVjSujPshOv1s9eDm5E6Gdz2B5iJy88RjEu7saB7plEkh2GVL0kxhwcXuAnASUVYldRizr63hhJCTi9XWXEDVIORPl+sJEqSctiUHsRokSRFfZUswLXAJuaTaJKLa2k8V4yKGdlSnq6kwlgwv6lXfzh4WgfbazlFRkYsiPpmi3v3FrSTSxfDeDe6OCfADxM6Gocifp/EzL+kLEb6bQT8EuKZYmTCqGKStg5rXZjVVlz1oj7RUx3SFSNbXh/TpvaZUwFQbIqzGMTEKGCypi9WtuBZShQXkpe7m9AWzBAsdSlkFQj4LlVLo+ngnwIacFd6Tw/MlNj7HJvBQgtgIr1BCYV3KrAcMCMRW21WPxgQBMZJPiK7tUF4LCfjEKoqLq/VcuxrFetFTaeZUJWDYtTgLVzmEUJyOH3pNszmsC1mwHP6UAlCgTP4bSglWacSnmByw4/FgElyuN3Iv17JNWOBFh6SMkuQltu7VWuUi/T5rDnRoMF5Y027QIQzSrxIUvBcJOjBlk3onX3SjGqagTuRbdXoDMV3toWVBjMcxARCt4waplfDsyi3Rmc0o5tGBGVaZxV5rRWFG/AFCjnwQv26ZcGk8JZdMr3GJBVIJGP8NxV4gysXDvkiZhYiJSFeDuSt";
		
		Assert.True(key.Public != keyString);
		Assert.True(keyString != key.Public);
		Assert.False(key.Public == keyString);
		Assert.False(keyString == key.Public);
		Assert.NotEqual(key.Public, keyString);
		Assert.NotEqual(keyString, key.Public);
	}

	[Fact]
	public void KeyNotNull() {
		using MlKemKey key = MlKemKey.ReadKeyFromFile("nockxtestkey.pem");
		MlKemPublicKey? publicKey = null;
		
		Assert.True(key.Public != publicKey);
		Assert.True(publicKey != key.Public);
		Assert.False(key.Public == publicKey);
		Assert.False(publicKey == key.Public);
		Assert.NotEqual(publicKey, key.Public);
		Assert.NotEqual(key.Public, publicKey);
	}
	
	[Fact]
	public void KeyNull() {
		MlKemPublicKey? publicKey = null;
		MlKemPublicKey? publicKey2 = null;
		
		Assert.True(publicKey2 == publicKey);
		Assert.True(publicKey == publicKey2);
		Assert.False(publicKey2 != publicKey);
		Assert.False(publicKey != publicKey2);
		Assert.Equal(publicKey, publicKey2);
		Assert.Equal(publicKey2, publicKey);
	}
}