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

import org.apache.commons.lang3.StringUtils;

/**
 * Deprecated class set for removal. Do not use.
 */ 
@Deprecated(since = "12.2", forRemoval = true)
public class Conv {
	
	private Conv() {
		// prevent instantiation
	}

    /**
	 * {@return a byte converted into a padded hex string}
	 * 
	 * @param b the byte
	 * @deprecated use {@link NumericUtilities#toPaddedHexString(byte)} instead
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public static String toHexString(byte b) {
		return NumericUtilities.toPaddedHexString(b);
    }

    /**
	 * {@return a short converted into a padded hex string}
	 * 
	 * @param s the short
	 * @deprecated use {@link NumericUtilities#toPaddedHexString(short)} instead
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public static String toHexString(short s) {
		return NumericUtilities.toPaddedHexString(s);
    }
    
	/**
	 * {@return an int converted into a padded hex string}
	 * 
	 * @param i the int
	 * @deprecated use {@link NumericUtilities#toPaddedHexString(int)} instead
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public static String toHexString(int i) {
		return NumericUtilities.toPaddedHexString(i);
    }

    /**
	 * {@return a long converted into a padded hex string}
	 * 
	 * @param l the long
	 * @deprecated use {@link NumericUtilities#toPaddedHexString(long)} instead
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public static String toHexString(long l) {
		return NumericUtilities.toPaddedHexString(l);
    }

    /**
	 * {@return a string that is extended to length {@code len} with zeroes}
	 * 
	 * @param s The string to pad
	 * @param len The length of the return string
	 * @deprecated use {@link StringUtils#leftPad(String, int, char)} instead
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public static String zeropad(String s, int len) {
		if (s == null) {
			s = "";
		}
		StringBuilder builder = new StringBuilder(s);
		int zerosNeeded = len - s.length();
		for (int i = 0; i < zerosNeeded; ++i) {
			builder.insert(0, '0');
		}
		return builder.toString();
	}
}
