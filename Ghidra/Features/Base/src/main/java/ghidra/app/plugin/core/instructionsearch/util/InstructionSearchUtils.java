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
package ghidra.app.plugin.core.instructionsearch.util;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin;
import ghidra.app.plugin.core.instructionsearch.model.InstructionMetadata;
import ghidra.app.plugin.core.instructionsearch.ui.SelectionModeWidget.InputMode;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.util.exception.InvalidInputException;

/**
 * Helper functions for the instruction search package.
 */
public class InstructionSearchUtils {

	/**
	 * Converts the given byte to a binary string.
	 * 
	 * @param byteval
	 * @return
	 */
	public static String toBinaryString(byte byteval) {
		StringBuilder sb = new StringBuilder("00000000");
		for (int bit = 0; bit < 8; bit++) {
			if (((byteval >> bit) & 1) > 0) {
				sb.setCharAt(7 - bit, '1');
			}
		}

		return sb.toString();
	}

	/**
	 * Returns true if the input is a valid binary string (all 0's and 1's).
	 * 
	 * @param input
	 * @return
	 */
	public static boolean isBinary(String input) {
		input = input.replaceAll("\\s", "");
		return input.matches("[01]+");
	}

	/**
	 * Returns a binary representation of the given hex string.  This will pad the string
	 * with '0's at the beginning to make a full byte.
	 * 
	 * Note that spaces are allowed in the input, but will be ignored.
	 * 
	 * @param hex
	 * @return
	 */
	public static String toBinary(String hex) {

		// To do this properly, convert each byte to an int, then turn that int into a string.  We
		// can't do it all as one operation because the hex string could represent a number too
		// large for an integer.

		// Chunk up the string into bytes, removing all spaces first.
		hex = hex.replaceAll("\\s", "");
		String[] byteStrs = hex.split("(?<=\\G.{2})");

		// This is the final string we'll be returning.
		String retString = "";

		// Loop over the byte strings, converting each one to a binary string.
		for (String byteStr : byteStrs) {
			int bint = Integer.parseInt(byteStr, 16);
			String bin = Integer.toBinaryString(bint);
			bin = padZeros(bin);
			retString += bin;
		}

		return retString;
	}

	/**
	 * Returns true if the input is a valid hex string.  
	 * 
	 * Note that spaces are allowed in the input, but are ignored.
	 * 
	 * @param input
	 * @return
	 */
	public static boolean isHex(String input) {
		input = input.replaceAll("\\s", "");
		return input.matches("[0-9a-fA-F]+");
	}

	/**
	 * Returns true if the input string represents a full byte of information.  
	 * 
	 * @param input
	 * @return
	 */
	public static boolean isFullHexByte(String input) {
		String text = input.replaceAll("\\s", "");
		return text.length() % 2 == 0;
	}

	/**
	 * Returns true if the input string represents a full byte of information.  
	 * 
	 * @param input
	 * @return
	 */
	public static boolean isFullBinaryByte(String input) {
		String text = input.replaceAll("\\s", "");
		return text.length() % 8 == 0;
	}

	/**
	 * Returns true if any bit in the given array is 'on' (set to 1).
	 * 
	 * @param bytearray
	 * @return
	 */
	public static boolean containsOnBit(byte[] bytearray) {
		for (byte element : bytearray) {
			int value = element & 0xff;
			if (value != 0) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Converts the given byte array to a binary string.
	 * 
	 * @param bs
	 * @return
	 */
	public static String toBinaryStr(byte[] bs) {

		StringBuilder sb = new StringBuilder();

		for (byte b : bs) {
			String s1 = String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0');
			sb.append(s1);
		}

		return sb.toString();
	}

	/**
	 * Returns a binary string with '.' characters where bits are masked.  This is used in
	 * formatting strings for display in the preview table.
	 *
	 * @param searchStr
	 * @param mask
	 * @return
	 * @throws InvalidInputException 
	 */
	public static String formatSearchString(String searchStr, String mask)
			throws InvalidInputException {
		String retStr = "";

		if (searchStr.length() != mask.length()) {
			throw new InvalidInputException("mask and search string not the same length.");
		}

		for (int i = 0; i < searchStr.length(); i++) {
			char valChar = searchStr.charAt(i);
			char maskChar = mask.charAt(i);
			if (valChar == '1') {
				retStr += "1";
			}
			else if (valChar == '0' && maskChar == '1') {
				retStr += "0";
			}
			else if (valChar == '0' && maskChar == '0') {
				retStr += ".";
			}
			else {
				retStr += "0";
			}
		}

		return retStr;
	}

	/**
	 * Performs an bitwise OR on the given arrays.
	 * 
	 * @param arr1
	 * @param arr2
	 * @return
	 */
	public static byte[] byteArrayOr(byte[] arr1, byte[] arr2) {
		byte[] result = new byte[arr1.length];

		if (arr1.length != arr2.length) {
			return null;
		}

		for (int x = 0; x < arr1.length; x++) {
			result[x] = (byte) (arr1[x] | arr2[x]);
		}

		return result;
	}

	/**
	 * Peforms a bitwise & on the given arrays.
	 * 
	 * @param mask
	 * @param bytes
	 * @return
	 */
	public static byte[] byteArrayAnd(byte[] mask, byte[] bytes) {
		byte[] result = new byte[bytes.length];

		if (mask.length != bytes.length) {
			throw new IllegalArgumentException("inappropriate mask");
		}

		for (int i = 0; i < bytes.length; i++) {
			result[i] = (byte) (mask[i] & bytes[i]);
		}
		return result;
	}

	/**
	* Converts the given binary instruction to hex.  
	* 
	* @param binaryStr binary string
	* @return hex string
	*/
	public static String toHex(String binaryStr, boolean zeroFill) {

		StringBuilder sb = new StringBuilder();

		// Do some initial formatting of the binary string to separate the bytes for easier
		// reading.
		binaryStr = binaryStr.replaceAll("\\s", "");
		binaryStr = addSpaceOnByteBoundary(binaryStr, InputMode.BINARY);

		// Now split the binary string on byte boundaries.
		String[] instrBytes = binaryStr.split("\\s");

		// For each byte, convert it to hex.  If there are any masked characters they will
		// be identified by a '.', so we can't show this as hex; just keep as binary and 
		// put in brackets to more easily identify.
		for (String binary : instrBytes) {

			if (binary.contains(".")) {
				sb.append("[").append(binary).append("]").append(" ");
			}
			else {

				// If we're here, then take the full 8 bits and convert to 
				// hex, making sure that if a single character is the result, we
				// zero-fill to make more readable.
				int decimal = Integer.parseInt(binary, 2);
				String hex = Integer.toString(decimal, 16);

				if (zeroFill && hex.length() == 1) {
					hex = "0" + hex;
				}
				sb.append(hex).append(" ");
			}
		}
		return sb.toString();
	}

	/**
	 * Converts the given binary string to hex, but isn't granular beyond the nibble level. 
	 * e.g. If the byte string is '00101...' the trailing '1' will be treated as a wildcard ('0010....').
	 * 
	 * Note: This is primarily for YARA work, since YARA does not get down to the bit level.
	 * 
	 * @param instr
	 * @return
	 */
	public static StringBuilder toHexNibblesOnly(String instr) {

		// Create the return string builder object.
		StringBuilder sb = new StringBuilder();

		// Do some initial formatting of the binary string to separate the bytes for easier
		// reading.
		instr = addSpaceOnByteBoundary(instr, InputMode.BINARY);

		// Now split the binary string on byte boundaries (spaces).
		String[] instrBytes = instr.split(" ");

		// For each byte, convert it to hex.  If there are any masked characters they will
		// be identified by a '.', so we can't show this as hex; just keep as binary and 
		// put in brackets to more easily identify.
		for (String binary : instrBytes) {
			if (binary.contains(".")) {

				// We have at least one masked bit, so we need to do some work.  Split the byte
				// into 2 nibbles and if either nibble has a '.', then we have to treat the entire
				// thing as a wildcard.
				String nibble1 = binary.substring(0, 4);
				String nibble2 = binary.substring(4, 8);
				if (nibble1.contains(".")) {
					nibble1 = ".";
				}
				else {
					int decimal = Integer.parseInt(nibble1, 2);
					nibble1 = Integer.toString(decimal, 16);
				}
				if (nibble2.contains(".")) {
					nibble2 = ".";
				}
				else {
					int decimal = Integer.parseInt(nibble2, 2);
					nibble2 = Integer.toString(decimal, 16);
				}
				sb.append(nibble1).append(nibble2).append(" ");
			}
			else {

				// If we're here, then take the full 8 bits and convert to 
				// hex, making sure that if a single character is the result, we
				// zero-fill to make more readable.
				int decimal = Integer.parseInt(binary, 2);
				String hex = Integer.toString(decimal, 16);

				if (hex.length() == 1) {
					hex = "0" + hex;
				}
				sb.append(hex).append(" ");
			}
		}
		return sb;
	}

	/**
	 * Returns a list of the sizes of each group, in terms of bytes, in the input string. 
	 * eg: if the input string is "1001 01 AAAA BB ABCDEF" the returned list will be 
	 * {2, 1, 2, 1, 3}.
	 * 
	 * @param source
	 * @param mode BINARY or HEX
	 * @return
	 * @throws Exception 
	 */
	public static List<Integer> getGroupSizes(String source, InputMode mode) throws Exception {
		List<Integer> sizes = new ArrayList<>();

		int modeSize = (mode == InputMode.BINARY) ? 8 : 2;

		// First split the input string on the space boundary, so we have a list of all the
		// groups.
		String[] groups = source.trim().split("\\s+");

		// Now loop over each group, adding the size of each to the return list. Also do a check
		// on each group; if it isn't an exact byte, then throw an exception.
		for (String group : groups) {
			if (group.length() < modeSize || group.length() % modeSize != 0) {
				throw new Exception("input is not a full byte(s)");
			}
			sizes.add(group.length() / modeSize);
		}

		return sizes;
	}

	/**
	 * Returns a list of all whitespaces in the given string. eg: if the input string is
	 * "aaa bb  cc     ddd e", the returned list will be: {" ", "  ", "     ", " "}.
	 * 
	 * Note 1: This will match newline characters as well, so those will be preserved in the 
	 *         returned strings.
	 * 
	 * Note 2: This is here so that we can 'remember' what the spaces are in an input string, and 
	 *         subsequently restore those spaces after manipulating (ie: converting from binary
	 *         to hex or vica-versa).
	 * 
	 * @param source
	 * @return
	 */
	public static List<String> getWhitespace(String source) {
		List<String> spaces = new ArrayList<>();

		Pattern whitespace = Pattern.compile("\\s+");
		Matcher matcher = whitespace.matcher(source);
		while (matcher.find()) {
			spaces.add(matcher.group());
		}

		return spaces;
	}

	/**
	 * Returns a {@link Byte} list from the given byte string.
	 * 
	 * @param byteStr
	 * @return
	 */
	public static List<Byte> toByteArray(String byteStr) {
		String[] byteStrs = byteStr.split("(?<=\\G.{8})");
		List<Byte> bytes = new ArrayList<>();

		for (String byteStr2 : byteStrs) {
			int bint = Integer.parseInt(byteStr2, 2);
			byte newbyte = (byte) bint;
			bytes.add(new Byte(newbyte));
		}

		return bytes;
	}

	/**
	 * Converts a {@link Byte} array to a {@link byte} array.
	 * 
	 * @param bytes
	 * @return
	 */
	public static byte[] toPrimitive(Byte[] bytes) {

		byte[] retList = new byte[bytes.length];
		for (int i = 0; i < bytes.length; i++) {
			retList[i] = bytes[i].byteValue();
		}

		return retList;
	}

	/**
	 * Formats a string by adding spaces on each byte boundary. The input mode specifies whether
	 * this boundary is every 2(hex) or 8(binary) characters.
	 *
	 * @param str
	 * @param mode hex or binary
	 * @return
	 */
	public static String addSpaceOnByteBoundary(String str, InputMode mode) {
		StringBuilder sb = new StringBuilder();

		// First remove all white spaces so we start from a clean string.
		str = str.replaceAll("\\s", "");

		int byteLength = 0;
		if (mode == InputMode.HEX) {
			byteLength = 2;
		}
		if (mode == InputMode.BINARY) {
			byteLength = 8;
		}

		// Now separate every 8th or 2nd char, depending on the format given.
		for (int i = 0; i < str.length(); i++) {
			sb.append(str.charAt(i));
			if ((i + 1) % byteLength == 0) {
				sb.append(" ");
			}
		}

		return sb.toString().trim();
	}

	/**
	 * Returns a list of {@link Address} items contained in the given {@link InstructionMetadata} 
	 * list.
	 *
	 * @param searchResults
	 * @return a list of addresses indicating starting positions of matches.
	 */
	public static List<Address> toAddressList(List<InstructionMetadata> searchResults) {
		List<Address> results = new ArrayList<Address>();
		for (InstructionMetadata meta : searchResults) {
			results.add(meta.getAddr());
		}

		return results;
	}

	/**
	 * Finds the {@link InstructionSearchPlugin}; returns null if it doesn't exist.
	 * 
	 * @param tool
	 * @return
	 */
	public static InstructionSearchPlugin getInstructionSearchPlugin(PluginTool tool) {
		List<Plugin> plugins = tool.getManagedPlugins();
		for (Plugin plugin : plugins) {
			if (plugin instanceof InstructionSearchPlugin) {
				return (InstructionSearchPlugin) plugin;
			}
		}

		return null;
	}

	/*********************************************************************************************
	 * PRIVATE METHODS
	 ********************************************************************************************/

	/**
	 * Adds zeros to the beginning of the binary string so it represents a full byte.
	 * 
	 * @param binStr
	 * @return
	 */
	private static String padZeros(String binStr) {
		String retString = binStr;

		if (binStr.length() < 8) {
			int diff = 8 - binStr.length();
			for (int i = 0; i < diff; i++) {
				retString = "0".concat(retString);
			}
		}

		return retString;
	}
}
