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
package ghidra.app.plugin.core.searchmem;

import java.util.*;

import javax.swing.event.ChangeListener;

import ghidra.util.HTMLUtilities;

public class HexSearchFormat extends SearchFormat {

	private static final String WILD_CARDS = ".?";
	private static final String HEX_CHARS = "0123456789abcdefABCDEF" + WILD_CARDS;
	private String statusText;

	public HexSearchFormat(ChangeListener listener) {
		super("Hex", listener);
	}

	@Override
	public String getToolTip() {
		return HTMLUtilities.toHTML("Interpret value as a sequence of\n" +
			"hex numbers, separated by spaces.\n" + "Enter '.' or '?' for a wildcard match");
	}

	@Override
	public SearchData getSearchData(String input) {
		List<String> list = new ArrayList<String>();
		StringTokenizer st = new StringTokenizer(input);
		while (st.hasMoreTokens()) {
			String token = st.nextToken();

			if (!isValidHex(token)) {
				return SearchData.createInvalidInputSearchData(statusText);
			}

			List<String> byteList = getByteStrings(token);
			if (!isBigEndian) {
				Collections.reverse(byteList);
			}
			list.addAll(byteList);
		}
		byte[] bytes = new byte[list.size()];
		byte[] mask = new byte[list.size()];
		for (int i = 0; i < list.size(); i++) {
			String byteString = list.get(i);
			bytes[i] = getByte(byteString);
			mask[i] = getMask(byteString);
		}
		return SearchData.createSearchData(input, bytes, mask);
	}

	private List<String> getByteStrings(String token) {

		if (isSingleWildCardChar(token)) {
			// treat single wildcards as a double wildcard entry, as this is more intuitive to users
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

	private boolean isValidHex(String str) {
		if (str.length() > 16) {
			statusText = "Max group size exceeded. Enter <space> to add more.";
			return false;
		}
		statusText = "";
		for (int i = 0; i < str.length(); i++) {
			if (HEX_CHARS.indexOf(str.charAt(i)) < 0) {
				return false;
			}
		}
		return true;
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

}
