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
import java.util.List;

public class MD5Utilities {

	public static final int SALT_LENGTH = HashUtilities.SALT_LENGTH;

	public static final int UNSALTED_HASH_LENGTH = HashUtilities.MD5_UNSALTED_HASH_LENGTH;
	public static final int SALTED_HASH_LENGTH = HashUtilities.MD5_SALTED_HASH_LENGTH;

	/**
	 * Generate MD5 hash in a hex character representation
	 * @param msg message text
	 * @return hex hash value in text format
	 */
	public static char[] getMD5Hash(char[] msg) {
		return HashUtilities.getSaltedHash(HashUtilities.MD5_ALGORITHM, new char[0], msg);
	}

	/**
	 * Generate salted MD5 hash for specified message.  Supplied salt is 
	 * returned as prefix to returned hash.
	 * @param salt digest salt (use empty string for no salt)
	 * @param msg message text
	 * @return salted hash using specified salt which is
	 * returned as a prefix to the hash
	 */
	public static char[] getSaltedMD5Hash(char[] salt, char[] msg) {
		return HashUtilities.getSaltedHash(HashUtilities.MD5_ALGORITHM, salt, msg);
	}

	/**
	 * Generate salted MD5 hash for specified message using random salt.  
	 * First 4-characters of returned hash correspond to the salt data.
	 * @param msg message text
	 * @return salted hash using randomly generated salt which is
	 * returned as a prefix to the hash
	 */
	public static char[] getSaltedMD5Hash(char[] msg) {
		char[] salt = new char[HashUtilities.SALT_LENGTH];
		for (int i = 0; i < salt.length; i++) {
			salt[i] = HashUtilities.getRandomLetterOrDigit();
		}
		return getSaltedMD5Hash(salt, msg);
	}

	/**
	 * Generate MD5 message digest hash for specified input stream.  
	 * Stream will be read until EOF is reached.
	 * @param in input stream
	 * @return message digest hash
	 * @throws IOException if reading input stream produces an error
	 */
	public static String getMD5Hash(InputStream in) throws IOException {
		return HashUtilities.getHash(HashUtilities.MD5_ALGORITHM, in);
	}

	/**
	 * Generate MD5 message digest hash for specified file contents.
	 * @param file file to be read
	 * @return message digest hash
	 * @throws IOException if opening or reading file produces an error
	 */
	public static String getMD5Hash(File file) throws IOException {
		return HashUtilities.getHash(HashUtilities.MD5_ALGORITHM, file);
	}

	/**
	 * Generate combined MD5 message digest hash for all values in the 
	 * specified values list.
	 * @param values list of text strings
	 * @return MD5 message digest hash
	 */
	public static String getMD5Hash(List<String> values) {
		return HashUtilities.getHash(HashUtilities.MD5_ALGORITHM, values);
	}

	/**
	 * Convert binary data to a sequence of hex characters.
	 * @param data binary data
	 * @return hex character representation of data
	 */
	public static char[] hexDump(byte[] data) {
		return HashUtilities.hexDump(data);
	}
}
