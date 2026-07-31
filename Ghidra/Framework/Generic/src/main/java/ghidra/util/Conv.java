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

/**
 * Legacy methods for converting between number data types without negative promotion. Most methods
 * have been deprecated off in favor of built-in Java methods.
 */ 
public class Conv {
	
	private Conv() {
		// prevent instantiation
	}

    /**
	 * Consider using {@link String#format(String, Object...) String.format("%02x", b)} instead.
	 * <p>
	 * Converts a byte into a padded hex string.
	 * 
	 * @param b the byte
	 * @return the padded hex string
	 */
	public static String toHexString(byte b) {
		return String.format("%02x", b);
    }

    /**
	 * Consider using {@link String#format(String, Object...) String.format("%04x", s)} instead.
	 * <p>
	 * Converts a short into a padded hex string.
	 * 
	 * @param s the short
	 * @return the padded hex string
	 */
	public static String toHexString(short s) {
		return String.format("%04x", s);
    }
    
	/**
	 * Consider using {@link String#format(String, Object...) String.format("%08x", i)} instead.
	 * <p>
	 * Converts an integer into a padded hex string.
	 * 
	 * @param i the integer
	 * @return the padded hex string
	 */
	public static String toHexString(int i) {
		return String.format("%08x", i);
    }

    /**
	 * Consider using {@link String#format(String, Object...) String.format("%016x", l)} instead.
	 * <p>
	 * Converts a long into a padded hex string.
	 * 
	 * @param l the long
	 * @return the padded hex string
	 */
	public static String toHexString(long l) {
		return String.format("%016x", l);
    }

    /**
	 * Returns a string that is extended to length len with zeroes.
	 * 
	 * @param s The string to pad
	 * @param len The length of the return string
	 * @return A string that has been left-padded with zeros to be of length len
	 */
	public static String zeropad(String s, int len) {
        if (s == null) s = "";
		StringBuilder builder = new StringBuilder(s);
        int zerosNeeded = len - s.length();
        for (int i = 0 ; i < zerosNeeded ; ++i) {
			builder.insert(0, '0');
        }
		return builder.toString();
    }
}
