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
 * {@link SearchFormat} for parsing and display bytes in a binary format. This format only
 * accepts 0s or 1s or wild card characters.
 */
class BinarySearchFormat extends SearchFormat {
	private static final String VALID_CHARS = "01x?.";
	private static final int MAX_GROUP_SIZE = 8;

	BinarySearchFormat() {
		super("Binary");
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

		byte[] bytes = getBytes(byteGroups);
		byte[] masks = getMask(byteGroups);
		return new MaskedByteSequenceByteMatcher(input, bytes, masks, settings);
	}

	@Override
	public String getToolTip() {
		return HTMLUtilities.toHTML(
			"Interpret value as a sequence of binary digits.\n" +
				"Spaces will start the next byte.  Bit sequences less\n" +
				"than 8 bits are padded with 0's to the left. \n" +
				"Enter 'x', '.' or '?' for a wildcard bit");
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

	private boolean hasInvalidChars(List<String> byteGroups) {
		for (String byteGroup : byteGroups) {
			if (hasInvalidChars(byteGroup)) {
				return true;
			}
		}
		return false;
	}

	private boolean hasInvalidChars(String string) {
		for (int i = 0; i < string.length(); i++) {
			if (VALID_CHARS.indexOf(string.charAt(i)) < 0) {
				return true;
			}
		}
		return false;
	}

	private byte getByte(String token) {
		byte b = 0;
		for (int i = 0; i < token.length(); i++) {
			b <<= 1;
			char c = token.charAt(i);
			if (c == '1') {
				b |= 1;
			}
		}
		return b;
	}

	/**
	 * Return a mask byte that has a bit set to 1 for each bit that is not a wildcard.  Any bits
	 * that aren't specified (i.e. token.lenght &lt; 8) are treated as valid test bits. 
	 * @param token the string of bits to determine a mask for.
	 */
	private byte getMask(String token) {
		byte b = 0;
		for (int i = 0; i < 8; i++) {
			b <<= 1;
			if (i < token.length()) {
				char c = token.charAt(i);
				if (c == '1' || c == '0') {
					b |= 1;
				}
			}
			else {
				b |= 1;
			}

		}

		return b;
	}

	private byte[] getBytes(List<String> byteGroups) {
		byte[] bytes = new byte[byteGroups.size()];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = getByte(byteGroups.get(i));
		}
		return bytes;
	}

	private byte[] getMask(List<String> byteGroups) {
		byte[] masks = new byte[byteGroups.size()];
		for (int i = 0; i < masks.length; i++) {
			masks[i] = getMask(byteGroups.get(i));
		}
		return masks;
	}

	@Override
	public String convertText(String text, SearchSettings oldSettings, SearchSettings newSettings) {
		SearchFormat oldFormat = oldSettings.getSearchFormat();
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

	private String getMaskedInputString(byte[] bytes, byte[] masks) {
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < bytes.length; i++) {
			for (int shift = 7; shift >= 0; shift--) {
				int bit = bytes[i] >> shift & 0x1;
				int maskBit = masks[i] >> shift & 0x1;
				builder.append(maskBit == 0 ? '.' : Integer.toString(bit));
			}
			builder.append(" ");
		}

		return builder.toString().trim();
	}

	@Override
	public SearchFormatType getFormatType() {
		return SearchFormatType.BYTE;
	}
}
