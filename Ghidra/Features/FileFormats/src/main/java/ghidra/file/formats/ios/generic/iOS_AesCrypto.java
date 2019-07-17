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

import ghidra.util.exception.CryptoException;

import java.io.InputStream;
import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class iOS_AesCrypto {
	public static final String CRYPTO_ALGORITHM = "AES";

	public static final String CRYPTO_TRANSFORMATION_CBC = "AES/CBC/NoPadding";

	private int keyLength;
	private Key key;
	private IvParameterSpec iv;

	public iOS_AesCrypto(byte[] key, byte[] iv) {
		if (key == null) {
			throw new IllegalArgumentException(
					"KEY is not specified, check the XML file and verify the KEY is correct.");
		}
		if (iv == null) {
			throw new IllegalArgumentException(
					"IV is not specified, check the XML file and verify the IV is correct.");
		}
		this.keyLength = key.length * 8;
		this.key = new SecretKeySpec(key, CRYPTO_ALGORITHM);
		this.iv = new IvParameterSpec(iv);
	}

	public byte[] encrypt(byte[] plainText) throws CryptoException {
		throw new CryptoException("encrypt() not implemented");
	}

	public InputStream decrypt(InputStream is) throws CryptoException {
		try {
			Cipher cipher = Cipher.getInstance(CRYPTO_TRANSFORMATION_CBC);

			int maxAllowedKeyLength = Cipher.getMaxAllowedKeyLength(CRYPTO_TRANSFORMATION_CBC);
			if (maxAllowedKeyLength < keyLength) {
				throw new InvalidKeyException("Attempt to decrypt using " + keyLength +
					" bit key size, but the JVM only supports " + maxAllowedKeyLength +
						" bit keys.  Install the JCE to fix this issue.");
			}

			cipher.init(Cipher.DECRYPT_MODE, key, iv);

			CipherInputStream cis = new CipherInputStream(is, cipher);

			return cis;
		}
		catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException e) {
			throw new CryptoException(e);
		}
	}

	public byte[] decrypt(byte[] cipherText) throws CryptoException {
		try {
			Cipher cipher = Cipher.getInstance(CRYPTO_TRANSFORMATION_CBC);

			int maxAllowedKeyLength = Cipher.getMaxAllowedKeyLength(CRYPTO_TRANSFORMATION_CBC);
			if (maxAllowedKeyLength < keyLength) {
				throw new InvalidKeyException("Attempt to decrypt using " + keyLength +
					" bit key size, but the JVM only supports " + maxAllowedKeyLength +
						" bit keys.  Install the JCE to fix this issue.");
			}

			cipher.init(Cipher.DECRYPT_MODE, key, iv);
			byte[] decrypted = cipher.doFinal(cipherText);
			return decrypted;
		}
		catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException
				| InvalidKeyException | InvalidAlgorithmParameterException
				| IllegalBlockSizeException e) {
			throw new CryptoException(e);
		}
	}

	public void update(byte[] update) throws CryptoException {
		throw new CryptoException("update() not implemented");
	}

}
