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
package ghidra.features.base.memsearch.format;

import java.util.*;

import ghidra.features.base.memsearch.gui.SearchSettings;
import ghidra.features.base.memsearch.matcher.*;
import ghidra.util.HTMLUtilities;

/**
 * {@link SearchFormat} for parsing and display bytes in a hex format. This format only 
 * accepts hex digits or wild card characters.
 */
class HexSearchFormat extends SearchFormat {

	private static final String WILD_CARDS = ".?";
	private static final String VALID_CHARS = "0123456789abcdefABCDEF" + WILD_CARDS;
	private static final int MAX_GROUP_SIZE = 16;

	HexSearchFormat() {
		super("Hex");
	}

	@Override
	public ByteMatcher parse(String input, SearchSettings settings) {
		input = input.trim();
		if (input.isBlank()) {
			return new InvalidByteMatcher("");
		}

		List<String> byteGroups = getByteGroups(input);

		if (hasInvalidChars(byteGroups)) {
			return new InvalidByteMatcher("Invalid character");
		}

		if (checkGroupSize(byteGroups)) {
			return new InvalidByteMatcher("Max group size exceeded. Enter <space> to add more.");
		}

		List<String> byteList = getByteList(byteGroups, settings);
		byte[] bytes = getBytes(byteList);
		byte[] masks = getMask(byteList);
		return new MaskedByteSequenceByteMatcher(input, bytes, masks, settings);
	}

	@Override
	public String getToolTip() {
		return HTMLUtilities.toHTML("Interpret value as a sequence of\n" +
			"hex numbers, separated by spaces.\n" + "Enter '.' or '?' for a wildcard match");
	}

	private byte[] getBytes(List<String> byteList) {
		byte[] bytes = new byte[byteList.size()];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = getByte(byteList.get(i));
		}
		return bytes;
	}

	private byte[] getMask(List<String> byteList) {
		byte[] masks = new byte[byteList.size()];
		for (int i = 0; i < masks.length; i++) {
			masks[i] = getMask(byteList.get(i));
		}
		return masks;
	}

	/**
	 * Returns the search mask for the given hex byte string.  Normal hex digits result
	 * in a "1111" mask and wildcard digits result in a "0000" mask.
	 */
	private byte getMask(String tok) {
		char c1 = tok.charAt(0);
		char c2 = tok.charAt(1);
		int index1 = WILD_CARDS.indexOf(c1);
		int index2 = WILD_CARDS.indexOf(c2);
		if (index1 >= 0 && index2 >= 0) {
			return (byte) 0x00;
		}
		if (index1 >= 0 && index2 < 0) {
			return (byte) 0x0F;
		}
		if (index1 < 0 && index2 >= 0) {
			return (byte) 0xF0;
		}
		return (byte) 0xFF;
	}

	/**
	 * Returns the byte value to be used for the given hex bytes.  Handles wildcard characters by
	 * return treating them as 0s.
	 */
	private byte getByte(String tok) {
		char c1 = tok.charAt(0);
		char c2 = tok.charAt(1);
		// note: the hexValueOf() method will turn wildcard chars into 0s
		return (byte) (hexValueOf(c1) * 16 + hexValueOf(c2));
	}

	private List<String> getByteList(List<String> byteGroups, SearchSettings settings) {
		List<String> byteList = new ArrayList<>();
		for (String byteGroup : byteGroups) {
			List<String> byteStrings = getByteStrings(byteGroup);
			if (!settings.isBigEndian()) {
				Collections.reverse(byteStrings);
			}
			byteList.addAll(byteStrings);
		}
		return byteList;
	}

	private List<String> getByteStrings(String token) {

		if (isSingleWildCardChar(token)) {
			// normally, a wildcard character represents a nibble. For convenience, if the there
			// is a single wild card character surrounded by whitespace, treat it
			// as if the entire byte is wild
			token += token;
		}
		else if (token.length() % 2 != 0) {
			// pad an odd number of nibbles with 0; assuming users leave off leading 0
			token = "0" + token;
		}

		int n = token.length() / 2;
		List<String> list = new ArrayList<String>(n);
		for (int i = 0; i < n; i++) {
			list.add(token.substring(i * 2, i * 2 + 2));
		}
		return list;
	}

	private boolean isSingleWildCardChar(String token) {
		if (token.length() == 1) {
			char c = token.charAt(0);
			return WILD_CARDS.indexOf(c) >= 0;
		}
		return false;
	}

	private boolean hasInvalidChars(List<String> byteGroups) {
		for (String byteGroup : byteGroups) {
			if (hasInvalidChars(byteGroup)) {
				return true;
			}
		}
		return false;
	}

	private boolean checkGroupSize(List<String> byteGroups) {
		for (String byteGroup : byteGroups) {
			if (byteGroup.length() > MAX_GROUP_SIZE) {
				return true;
			}
		}
		return false;
	}

	private List<String> getByteGroups(String input) {
		List<String> list = new ArrayList<String>();
		StringTokenizer st = new StringTokenizer(input);
		while (st.hasMoreTokens()) {
			list.add(st.nextToken());
		}
		return list;
	}

	private boolean hasInvalidChars(String string) {
		for (int i = 0; i < string.length(); i++) {
			if (VALID_CHARS.indexOf(string.charAt(i)) < 0) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns the value of the given hex digit character.
	 */
	private int hexValueOf(char c) {
		if ((c >= '0') && (c <= '9')) {
			return c - '0';
		}
		else if ((c >= 'a') && (c <= 'f')) {
			return c - 'a' + 10;
		}
		else if ((c >= 'A') && (c <= 'F')) {
			return c - 'A' + 10;
		}
		else {
			return 0;
		}
	}

	@Override
	public String convertText(String text, SearchSettings oldSettings, SearchSettings newSettings) {
		SearchFormat oldFormat = oldSettings.getSearchFormat();
		if (oldFormat.getClass() == getClass()) {
			return text;
		}
		if (oldFormat.getFormatType() != SearchFormatType.STRING_TYPE) {
			ByteMatcher byteMatcher = oldFormat.parse(text, oldSettings);
			if ((byteMatcher instanceof MaskedByteSequenceByteMatcher matcher)) {
				byte[] bytes = matcher.getBytes();
				byte[] mask = matcher.getMask();
				return getMaskedInputString(bytes, mask);
			}
		}

		return isValidText(text, newSettings) ? text : "";
	}

	private String getMaskedInputString(byte[] bytes, byte[] mask) {
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < bytes.length; i++) {
			String s = String.format("%02x", bytes[i]);
			builder.append((mask[i] & 0xf0) == 0 ? "." : s.charAt(0));
			builder.append((mask[i] & 0x0f) == 0 ? "." : s.charAt(1));
			builder.append(" ");
		}

		return builder.toString().trim();
	}

	@Override
	public SearchFormatType getFormatType() {
		return SearchFormatType.BYTE;
	}
}
