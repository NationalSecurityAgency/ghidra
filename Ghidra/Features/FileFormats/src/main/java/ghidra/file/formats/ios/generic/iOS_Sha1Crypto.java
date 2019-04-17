/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.file.formats.ios.generic;

import java.security.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import ghidra.util.exception.CryptoException;

public class iOS_Sha1Crypto {
	private static final String CRYPTO_ALGORITHM = "HmacSHA1";

	private Key macKey;
	private Mac mac;

	public iOS_Sha1Crypto(byte [] key) throws CryptoException {
		this.macKey = new SecretKeySpec(key, CRYPTO_ALGORITHM);
		try {
			this.mac = Mac.getInstance(CRYPTO_ALGORITHM);
			this.mac.init(macKey);
		}
		catch (NoSuchAlgorithmException e) {
			throw new CryptoException(e);
		}
		catch (InvalidKeyException e) {
			throw new CryptoException(e);
		}
	}

	public void update(byte[] update) {
		mac.update(update);
	}

	public byte [] encrypt(byte [] plainText) throws CryptoException {
		throw new CryptoException("encrypt() not implemented");
	}

	public byte [] decrypt(byte [] cipherText) throws CryptoException {
		try {
			return mac.doFinal(cipherText);
		}
		catch (IllegalStateException e) {
			throw new CryptoException(e);
		}
	}

	public byte [] decrypt() throws CryptoException {
		try {
			return mac.doFinal();
		}
		catch (IllegalStateException e) {
			throw new CryptoException(e);
		}
	}
}
