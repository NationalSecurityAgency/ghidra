/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
 * Class with static methods formatting values in hex.  
 */
public class StringFormat {

	private StringFormat() {
	}
	/**
	 * Gets a hexadecimal representation of a byte value.
	 * @param b the byte value
	 * @return the byte as a hexadecimal string.
	 */
	public static String hexByteString(byte b) {
		String rep = Integer.toHexString(b&0xff).toUpperCase();
		if (rep.length() == 1) {
			return "0"+rep;
		}
		return rep;
	}
	
	/**
	 * Gets a hexadecimal representation of a short value.
	 * @param s the short value
	 * @return the short as a hexadecimal string.
	 */
	public static String hexWordString(short s) {
		String rep = Integer.toHexString(s&0xffff).toUpperCase();
		return padIt(rep, 4, (char)0, true);
	}


	/**
	 * Creates a string prepended with zeros, if padding is indicated, and adds 
	 * the indicated endchar as the suffix.
	 * @param str the original string
	 * @param padlen length of the padded string without the suffix character.
	 * @param endchar the suffix character
	 * @param padded if true then prepend with zeros
	 * @return return the possibly padded string containing the suffix.
	 */
	public static String padIt(String str, int padlen, char endchar, boolean padded) {
		String pad = "0000000000000000000000000000000000000000000000000000000000000000";
		StringBuffer buffer = new StringBuffer();

		// pad the front with zeroes
		if (padded) {
			int len = str.length();

			if (len < padlen) {
				buffer.append(pad.substring(0,padlen-len)); 
			}
		}
		// add the number
		buffer.append(str);

		// add end char if needed
		if (endchar != 0) {
			buffer.append(endchar);
		}
		return buffer.toString();
	}


}
