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
package ghidra.file.formats.cart;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.util.Arrays;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

/**
 * StreamProcessor implementation to decrypt the data as it is being read.
 */
public class CartV1StreamDecryptor extends CartV1StreamProcessor {
	private Cipher cipher;

	/**
	 * Construct a stream decryptor with the specified key.
	 *
	 * @param delegate InputStream to read and apply decryption
	 * @param arc4Key The ARC4 key to use
	 * @throws CartInvalidARC4KeyException If the key is bad, null or too short.
	 */
	public CartV1StreamDecryptor(InputStream delegate, byte[] arc4Key)
			throws CartInvalidARC4KeyException {
		super(delegate);

		if (arc4Key == null) {
			throw new CartInvalidARC4KeyException("Invalid null CaRT key.");
		}
		else if (arc4Key.length != CartV1Constants.ARC4_KEY_LENGTH) {
			arc4Key = Arrays.copyOf(arc4Key, CartV1Constants.ARC4_KEY_LENGTH);
		}

		Key key = new SecretKeySpec(arc4Key, "ARCFOUR");
		try {
			cipher = Cipher.getInstance("ARCFOUR");
			cipher.init(Cipher.DECRYPT_MODE, key, cipher.getParameters());
		}
		catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException e) {
			throw new CartInvalidARC4KeyException("CaRT key error " + e);
		}
	}

	/**
	 * Read the next chunk in the stream and decrypt
	 *
	 * @return True if more data is now available, False otherwise.
	 * @throws IOException If there is a read failure of the data
	 */
	@Override
	protected boolean readNextChunk() throws IOException {
		byte[] readBuffer = new byte[DEFAULT_BUFFER_SIZE];

		// Reset the current chunk and offset
		currentChunk = null;
		chunkPos = 0;

		if (cipher == null) {
			return false;
		}

		int bytesRead = delegate.read(readBuffer);

		if (bytesRead <= 0) {
			// No more bytes available finalize the decryption
			try {
				currentChunk = cipher.doFinal();
			}
			catch (IllegalBlockSizeException | BadPaddingException e) {
				throw new IOException(e);
			}
			finally {
				// prevents trying to call doFinal() again
				cipher = null;
			}
		}
		else {
			currentChunk = cipher.update(readBuffer, 0, bytesRead);
		}

		return currentChunk != null && currentChunk.length > 0;
	}
}
