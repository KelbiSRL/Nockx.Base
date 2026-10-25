# Base for Nockx™
<img src="nockx-logo.png" width="400px" align="right" style="float: right;" alt="nockx bear logo"/>

This library contains all the cryptographic operations for [Nockx™](https://nockx.com).<br/>
The types of cryptography implemented are RSA, ML-KEM, ML-DSA and AES-GCM.

## Expected usage

While all cryptography types are usable individually, the intended way of use is encrypting with a `NockxKey`, which combines all these methods for maximum security.<br/>
After encryption, a signature of the encrypted data should be created and before decrypting, this signature should be verified.

### Copyright notice

Copyright &copy; 2026 Kelbi S.R.L.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.