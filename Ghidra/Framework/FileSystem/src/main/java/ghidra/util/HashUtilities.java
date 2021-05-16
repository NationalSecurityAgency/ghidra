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
package ghidra.util;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import generic.random.SecureRandomFactory;

public class HashUtilities {

	public static String MD5_ALGORITHM = "MD5";
	public static String SHA256_ALGORITHM = "SHA-256";

	public static final int SALT_LENGTH = 4;

	public static final int MD5_UNSALTED_HASH_LENGTH = 32;
	public static final int MD5_SALTED_HASH_LENGTH = MD5_UNSALTED_HASH_LENGTH + SALT_LENGTH;

	public static final int SHA256_UNSALTED_HASH_LENGTH = 64;
	public static final int SHA256_SALTED_HASH_LENGTH = SHA256_UNSALTED_HASH_LENGTH + SALT_LENGTH;

	static char getRandomLetterOrDigit() {
		int val = (SecureRandomFactory.getSecureRandom().nextInt() % 62); // 0-9,A-Z,a-z (10+26+26=62)
		if (val < 0) {
			val = -val;
		}
		int c = '0' + val;
		if (c > '9') {
			c = 'A' + (val - 10);
		}
		if (c > 'Z') {
			c = 'a' + (val - 36);
		}
		return (char) c;
	}

	/**
	 * Generate hash in a hex character representation
	 * @param algorithm message digest algorithm
	 * @param msg message text
	 * @return hex hash value in text format
	 * @throws IllegalArgumentException if specified algorithm is not supported
	 * @see MessageDigest for supported algorithms
	 */
	public static char[] getHash(String algorithm, char[] msg) {
		return getSaltedHash(algorithm, new char[0], msg);
	}

	/**
	 * Generate salted hash for specified message.  Supplied salt is 
	 * returned as prefix to returned hash.
	 * @param algorithm message digest algorithm
	 * @param salt digest salt (use empty string for no salt)
	 * @param msg message text
	 * @return salted hash using specified salt which is
	 * returned as a prefix to the hash
	 * @throws IllegalArgumentException if specified algorithm is not supported
	 * @see MessageDigest for supported hash algorithms
	 */
	public static char[] getSaltedHash(String algorithm, char[] salt, char[] msg) {
		MessageDigest messageDigest = getMessageDigest(algorithm);
		byte[] msgBytes = new byte[msg.length + salt.length];
		try {
			for (int i = 0; i < salt.length; i++) {
				msgBytes[i] = (byte) salt[i];
			}
			for (int i = 0; i < msg.length; i++) {
				msgBytes[i + salt.length] = (byte) msg[i];
			}

			char[] hash = hexDump(messageDigest.digest(msgBytes));

			char[] saltedHash = new char[hash.length + SALT_LENGTH];
			System.arraycopy(salt, 0, saltedHash, 0, salt.length);
			System.arraycopy(hash, 0, saltedHash, salt.length, hash.length);
			return saltedHash;
		}
		finally {
			// attempt to remove message from memory since it may be a password.
			Arrays.fill(msgBytes, (byte) 0);
		}
	}

	/**
	 * Generate salted hash for specified message using random salt.  
	 * First 4-characters of returned hash correspond to the salt data.
	 * @param algorithm message digest algorithm
	 * @param msg message text
	 * @return salted hash using randomly generated salt which is
	 * returned as a prefix to the hash
	 * @throws IllegalArgumentException if specified algorithm is not supported
	 * @see MessageDigest for supported hash algorithms
	 */
	public static char[] getSaltedHash(String algorithm, char[] msg) {
		char[] salt = new char[SALT_LENGTH];
		for (int i = 0; i < SALT_LENGTH; i++) {
			salt[i] = getRandomLetterOrDigit();
		}
		return getSaltedHash(algorithm, salt, msg);
	}

	/**
	 * Generate message digest hash for specified input stream.  Stream will be read
	 * until EOF is reached.
	 * @param algorithm message digest algorithm
	 * @param in input stream
	 * @return message digest hash
	 * @throws IOException if reading input stream produces an error
	 * @throws IllegalArgumentException if specified algorithm is not supported
	 * @see MessageDigest for supported hash algorithms
	 */
	public static String getHash(String algorithm, InputStream in) throws IOException {
		MessageDigest messageDigest = getMessageDigest(algorithm);
		byte[] buf = new byte[16 * 1024];
		int cnt;
		while ((cnt = in.read(buf)) >= 0) {
			messageDigest.update(buf, 0, cnt);
		}
		return NumericUtilities.convertBytesToString(messageDigest.digest());
	}

	/**
	 * Generate message digest hash for specified file contents.
	 * @param algorithm message digest algorithm
	 * @param file file to be read
	 * @return message digest hash
	 * @throws IOException if opening or reading file produces an error
	 * @throws IllegalArgumentException if specified algorithm is not supported
	 * @see MessageDigest for supported hash algorithms
	 */
	public static String getHash(String algorithm, File file) throws IOException {
		try (FileInputStream in = new FileInputStream(file)) {
			return getHash(algorithm, in);
		}
	}

	/**
	 * Generate combined message digest hash for all values in the 
	 * specified values list.
	 * @param algorithm message digest algorithm
	 * @param values list of text strings
	 * @return message digest hash
	 * @throws IllegalArgumentException if specified algorithm is not supported
	 * @see MessageDigest for supported hash algorithms
	 */
	public static String getHash(String algorithm, List<String> values) {
		MessageDigest messageDigest = getMessageDigest(algorithm);
		for (String value : values) {
			if (value != null) {
				messageDigest.update(value.getBytes());
			}
		}
		return NumericUtilities.convertBytesToString(messageDigest.digest());
	}

	/**
	 * Generate combined message digest hash for the bytes in the specified array.
	 *  
	 * @param algorithm message digest algorithm
	 * @param values array of bytes to hash
	 * @return message digest hash
	 * @throws IllegalArgumentException if specified algorithm is not supported
	 * @see MessageDigest for supported hash algorithms
	 */
	public static String getHash(String algorithm, byte[] values) {
		MessageDigest messageDigest = getMessageDigest(algorithm);
		messageDigest.update(values);
		return NumericUtilities.convertBytesToString(messageDigest.digest());
	}

	private static MessageDigest getMessageDigest(String algorithm) {
		try {
			return MessageDigest.getInstance(algorithm);
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException("Algorithm not supported: " + algorithm);
		}
	}

	/**
	 * Convert binary data to a sequence of hex characters.
	 * @param data binary data
	 * @return hex character representation of data
	 */
	public static char[] hexDump(byte[] data) {
		char buf[] = new char[data.length * 2];
		for (int i = 0; i < data.length; i++) {
			String b = Integer.toHexString(data[i] & 0xFF);
			if (b.length() < 2) {
				buf[i * 2 + 0] = '0';
				buf[i * 2 + 1] = b.charAt(0);
			}
			else {
				buf[i * 2 + 0] = b.charAt(0);
				buf[i * 2 + 1] = b.charAt(1);
			}
		}
		return buf;
	}
}
