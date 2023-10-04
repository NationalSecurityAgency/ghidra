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

import java.io.*;
import java.nio.charset.StandardCharsets;

import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Decryptor object for the CaRT format (Version 1).
 */
public class CartV1Decryptor {
	private byte[] arc4Key;

	/**
	 * Static function to decrypt the specified buffer with the specified key.
	 *
	 * @param arc4Key         The ARC4 key to use
	 * @param encryptedBuffer The buffer to decrypt
	 * @return The decrypted buffer bytes or null on failure.
	 * @throws CartInvalidARC4KeyException If the key is invalid
	 * @throws IOException If there is an error reading from the buffer
	 * @throws CancelledException If the decryption is cancelled from the monitor
	 */
	public static byte[] decrypt(byte[] arc4Key, byte[] encryptedBuffer)
			throws CartInvalidARC4KeyException, CancelledException, IOException {

		return CartV1Decryptor.decrypt(arc4Key, encryptedBuffer, null);
	}

	/**
	 * Static function to decrypt the specified buffer with the specified key.
	 *
	 * @param arc4Key         The ARC4 key to use
	 * @param encryptedBuffer The buffer to decrypt
	 * @param monitor         The monitor UI element for the user to see progress or cancel
	 * @return The decrypted buffer bytes or null on failure.
	 * @throws CartInvalidARC4KeyException If the key is invalid
	 * @throws IOException If there is an error reading from the buffer
	 * @throws CancelledException If the decryption is cancelled from the monitor
	 */
	public static byte[] decrypt(byte[] arc4Key, byte[] encryptedBuffer, TaskMonitor monitor)
			throws CartInvalidARC4KeyException, CancelledException, IOException {
		CartV1Decryptor decryptor = new CartV1Decryptor(arc4Key);

		return decryptor.decrypt(encryptedBuffer, monitor);
	}

	/**
	 * Static function to decrypt the specified buffer with the specified key and
	 * convert the output to a UTF-8 String.
	 *
	 * @param arc4Key         The ARC4 key to use
	 * @param encryptedBuffer The buffer to decrypt
	 * @return The decrypted String or null on failure.
	 * @throws CartInvalidARC4KeyException If the key is invalid
	 * @throws IOException If there is an error reading from the buffer
	 */
	public static String decryptToString(byte[] arc4Key, byte[] encryptedBuffer)
			throws CartInvalidARC4KeyException, IOException {
		return decryptToString(arc4Key, encryptedBuffer, null);
	}

	/**
	 * Static function to decrypt the specified buffer with the specified key and
	 * convert the output to a UTF-8 String.
	 *
	 * @param arc4Key         The ARC4 key to use
	 * @param encryptedBuffer The buffer to decrypt
	 * @param monitor         The monitor UI element for the user to see progress or cancel
	 * @return The decrypted String or null on failure.
	 * @throws CartInvalidARC4KeyException If the key is invalid
	 * @throws IOException If there is an error reading from the buffer
	 */
	public static String decryptToString(byte[] arc4Key, byte[] encryptedBuffer,
			TaskMonitor monitor) throws CartInvalidARC4KeyException, IOException {
		CartV1Decryptor decryptor = new CartV1Decryptor(arc4Key);
		return decryptor.decryptToString(encryptedBuffer, monitor);
	}

	/**
	 * Construct a decryptor with the specified key.
	 *
	 * @param arc4Key The ARC4 key to use
	 * @throws CartInvalidARC4KeyException If the key is bad, null or too short.
	 */
	public CartV1Decryptor(byte[] arc4Key) throws CartInvalidARC4KeyException {
		setKey(arc4Key);
	}

	/**
	 * Throws an exception if the key is not valid.
	 *
	 * @throws CartInvalidARC4KeyException If the key is invalid.
	 */
	public void throwIfInvalid() throws CartInvalidARC4KeyException {
		throwIfInvalid(this.arc4Key);
	}

	/**
	 * Throws an exception if the specified key is not valid.
	 *
	 * @param proposedARC4Key The ARC4 key being proposed to use.
	 * @throws CartInvalidARC4KeyException If the key is bad, null or too short.
	 */
	public void throwIfInvalid(byte[] proposedARC4Key) throws CartInvalidARC4KeyException {
		if (proposedARC4Key == null) {
			throw new CartInvalidARC4KeyException("Invalid null CaRT key.");
		}
		else if (proposedARC4Key.length != CartV1Constants.ARC4_KEY_LENGTH) {
			throw new CartInvalidARC4KeyException("Invalid CaRT key length.");
		}
	}

	/**
	 * Set the ARC4 key for this decryptor instance.
	 *
	 * @param arc4Key The ARC4 key to use
	 * @throws CartInvalidARC4KeyException If the key is bad, null or too short.
	 */
	public void setKey(byte[] arc4Key) throws CartInvalidARC4KeyException {
		throwIfInvalid(arc4Key);

		this.arc4Key = arc4Key;
	}

	/**
	 * Decrypt the specified buffer with object's key.
	 *
	 * @param encryptedBuffer The buffer to decrypt
	 * @return The decrypted buffer bytes or null on failure.
	 * @throws CartInvalidARC4KeyException If the key is invalid
	 * @throws IOException If there is an error reading from the buffer
	 */
	public byte[] decrypt(byte[] encryptedBuffer) throws CartInvalidARC4KeyException, IOException {
		return this.decrypt(encryptedBuffer, (TaskMonitor) null);
	}

	/**
	 * Decrypt the specified buffer with object's key.
	 *
	 * @param encryptedBuffer The buffer to decrypt
	 * @param monitor         The monitor UI element for the user to see progress or cancel
	 * @return The decrypted buffer bytes or null on failure.
	 * @throws CartInvalidARC4KeyException If the key is invalid
	 * @throws IOException If there is an error reading from the buffer
	 */
	public byte[] decrypt(byte[] encryptedBuffer, TaskMonitor monitor)
			throws CartInvalidARC4KeyException, IOException {
		try {
			CartV1StreamDecryptor decryptor =
				new CartV1StreamDecryptor(new ByteArrayInputStream(encryptedBuffer), arc4Key);
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();

			FSUtilities.streamCopy(decryptor, buffer, TaskMonitor.dummyIfNull(monitor));

			buffer.flush();

			return buffer.toByteArray();
		}
		catch (CancelledException e) {
			// ignore
		}

		return null;
	}

	/**
	 * Decrypt the specified buffer with the object's key and convert the output to
	 * a UTF-8 String.
	 *
	 * @param encryptedBuffer The buffer to decrypt
	 * @return The decrypted String or null on failure.
	 * @throws CartInvalidARC4KeyException If the key is invalid
	 * @throws IOException If there is an error reading from the buffer
	 */
	public String decryptToString(byte[] encryptedBuffer)
			throws CartInvalidARC4KeyException, IOException {
		return this.decryptToString(encryptedBuffer, (TaskMonitor) null);
	}

	/**
	 * Decrypt the specified buffer with the object's key and convert the output to
	 * a UTF-8 String.
	 *
	 * @param encryptedBuffer The buffer to decrypt
	 * @param monitor         The monitor UI element for the user to see progress or cancel
	 * @return The decrypted String or null on failure.
	 * @throws CartInvalidARC4KeyException If the key is invalid
	 * @throws IOException If there is an error reading from the buffer
	 */
	public String decryptToString(byte[] encryptedBuffer, TaskMonitor monitor)
			throws CartInvalidARC4KeyException, IOException {
		byte[] decryptedBuffer = decrypt(encryptedBuffer, monitor);

		if (decryptedBuffer != null) {
			return new String(decryptedBuffer, StandardCharsets.UTF_8);
		}

		return null;
	}

	/**
	 * Get the ARC4 key being used by the object.
	 *
	 * @return The bytes of the ARC4 key.
	 */
	protected byte[] getARC4Key() {
		return arc4Key;
	}
}
