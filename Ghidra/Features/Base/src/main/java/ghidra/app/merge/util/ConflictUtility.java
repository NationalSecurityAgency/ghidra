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
package ghidra.app.merge.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.util.DiffUtility;
import ghidra.util.HTMLUtilities;

/**
 * <code>ConflictUtility</code> provides some constants and static methods 
 * used by the Listing Merge portion of the multi-user merge.
 * For now, the VariousChoicesPanel and VerticalChoicesPanel use HTML in
 * JLabels to display color etc. This is because they also show radiobuttons
 * and checkboxes.
 */
public class ConflictUtility {

	// Strings defining the RGBs to use for colors in HTML.
	public static String MAROON = "#990000";
	public static String GREEN = "#009900";
	public static String BLUE = "#000099";
	public static String PURPLE = "#990099";
	public static String DARK_CYAN = "#009999";
	public static String OLIVE = "#999900";
	public static String ORANGE = "#FF9900";
	public static String PINK = "#FF9999";
	public static String YELLOW = "#FFFF00";
	public static String GRAY = "#888888";

	/** Color to use for displaying addresses. */
	public static String ADDRESS_COLOR = MAROON;
	/** Color to use for displaying numeric values. */
	public static String NUMBER_COLOR = MAROON;
	/** Color to use for displaying emphasized text. (for example, this is used when displaying symbols.) */
	public static String EMPHASIZE_COLOR = MAROON;
	/** Color to use for displaying offsets. */
	public static String OFFSET_COLOR = MAROON;

	/** String to display when a version doesn't have a value for an element of the program. */
	public static String NO_VALUE = "-- No Value --";

	/** Puts HTML and BODY tags around the string. */
	public static String wrapAsHTML(String text) {
		return "<html><body>" + text + "</body></html>";
	}

	/**
	 * This creates color text by wrapping a text string with an HTML font tag 
	 * that has a color attribute.
	 * @param rgbColor (eg. "#8c0000")
	 * @param text the text to be colored
	 * @return the tagged string.
	 */
	public static String colorString(String rgbColor, String text) {
		return "<font color=\"" + rgbColor + "\">" + text + "</font>";
	}

	/**
	 * This creates a colored number by converting the number to a string and 
	 * wrapping it with an HTML font tag that has a color attribute.
	 * @param rgbColor (eg. "#8c0000")
	 * @param value the integer number
	 * @return the tagged string.
	 */
	public static String colorString(String rgbColor, int value) {
		return "<font color=\"" + rgbColor + "\">" + value + "</font>";
	}

	/**
	 * Creates a string for the number of spaces indicated that can be used in HTML.
	 * This string can be used to preserve spacing.
	 * @param num the number of spaces
	 * @return the string representing that many spaces in HTML.
	 */
	public static String spaces(int num) {
		StringBuffer buf = new StringBuffer(6 * num);
		for (int i = 0; i < num; i++) {
			buf.append("&nbsp;");
		}
		return buf.toString();
	}

	/**
	 * Adds a color number to the indicated string  buffer.
	 * @param buf the string buffer
	 * @param value the integer number
	 */
	public static void addCount(StringBuffer buf, int value) {
		buf.append(getNumberString(value));
	}

	/**
	 * Adds a color program address to the indicated string buffer.
	 * @param buf the string buffer
	 * @param addr the program address
	 */
	public static void addAddress(StringBuffer buf, Address addr) {
		buf.append(getAddressString(addr));
	}

	/**
	 * Creates a standard conflict count message. This indicates which conflict
	 * you are resolving of some total number of conflicts.
	 * @param conflictNum the current conflict number.
	 * @param totalConflicts the total number of conflicts
	 * @return the message string containing HTML tags.
	 */
	public static String getConflictCount(int conflictNum, int totalConflicts) {
		StringBuffer buf = new StringBuffer();
		buf.append("Conflict #");
		addCount(buf, conflictNum);
		buf.append(" of ");
		addCount(buf, totalConflicts);
		return buf.toString();
	}

	/**
	 * Creates a standard conflict count message for an address. This indicates which conflict
	 * you are resolving of some total number of conflicts at a given address.
	 * @param conflictNum the current conflict number.
	 * @param totalConflicts the total number of conflicts
	 * @param addr the address for the indicated conflicts.
	 * @return the message string containing HTML tags.
	 */
	public static String getConflictCount(int conflictNum, int totalConflicts, Address addr) {
		StringBuffer buf = new StringBuffer(getConflictCount(conflictNum, totalConflicts));
		buf.append(" @ address: ");
		addAddress(buf, addr);
		return buf.toString();
	}

	/**
	 * Creates a standard conflict count message for an address range. This indicates which conflict
	 * you are resolving of some total number of conflicts for a given address range.
	 * @param conflictNum the current conflict number.
	 * @param totalConflicts the total number of conflicts
	 * @param range the address range for the indicated conflicts.
	 * @return the message string containing HTML tags.
	 */
	public static String getConflictCount(int conflictNum, int totalConflicts, AddressRange range) {
		StringBuffer buf = new StringBuffer(getConflictCount(conflictNum, totalConflicts));
		buf.append(" for address range: ");
		addAddress(buf, range.getMinAddress());
		buf.append("-");
		addAddress(buf, range.getMaxAddress());
		return buf.toString();
	}

	/**
	 * Creates a standard address set conflict count message. This indicates 
	 * which address or address range with conflicts you are resolving of some 
	 * total number of addresses or address ranges with conflicts.
	 * @param addressNum the current conflicting address number.
	 * @param totalAddresses the total number of conflicting addresses.
	 * @param isRange true if the current conflict is for an address range.
	 * @return the message string containing HTML tags.
	 */
	public static String getAddressConflictCount(int addressNum, int totalAddresses,
			boolean isRange) {
		StringBuffer buf = new StringBuffer();
		if (isRange) {
			buf.append("Address range #");
		}
		else {
			buf.append("Address #");
		}
		addCount(buf, addressNum);
		buf.append(" of ");
		addCount(buf, totalAddresses);
		buf.append(" with conflicts");
		return buf.toString();
	}

	/**
	 * Surrounds the originalString with HTML tags. It truncates the string at
	 * truncLength number of characters and adds "..." if it is longer than truncLength.
	 * It also replaces newline characters with HTML break tags.
	 * <br>
	 * Warning: The originalString should not contain special HTML tags. If it does,
	 * they may get truncated in the middle of a tag.
	 * @param originalString
	 * @param truncLength truncate at this length
	 * @return the truncated message string containing HTML tags.
	 */
	public static String getTruncatedHTMLString(String originalString, int truncLength) {
		if (originalString == null) {
			originalString = "";
		}
		int originalLength = originalString.length();
		boolean shouldTruncate = originalLength > truncLength;
		String truncString = originalString;
		if (shouldTruncate) {
			truncString = originalString.substring(0, truncLength - 3) + "...";
		}
		return wrapAsHTML(replaceNewLines(truncString));
	}

	/**
	 * Replaces new lines in the given string with HTML break tags.
	 * @param text the original string containing new lines.
	 * @return the new string containing break tags.
	 */
	private static String replaceNewLines(String text) {
		int length = text.length();
		StringBuffer buf = new StringBuffer();
		int start = 0;
		while (start < length) {
			int index = text.indexOf('\n', start);
			if (index == -1) {
				buf.append(text.substring(start));
				start = length;
			}
			else {
				buf.append(text.substring(start, index));
				buf.append("<br>");
				start = index + 1;
			}
		}
		return buf.toString();
	}

	/**
	 * Creates a string containing HTML tags to represent the address in color.
	 * @param address the program address.
	 * @return the message string containing HTML tags.
	 */
	public static String getAddressString(Address address) {
		return colorString(ADDRESS_COLOR,
			((address != null) ? HTMLUtilities.escapeHTML(address.toString()) : ""));
	}

	/**
	 * Creates a string containing HTML tags to represent the address in color.
	 * @param address the program address.
	 * @param showAddressSpace true indicates the address string should show the address space.
	 * @return the message string containing HTML tags.
	 */
	public static String getAddressString(Address address, boolean showAddressSpace) {
		return colorString(ADDRESS_COLOR,
			((address != null) ? HTMLUtilities.escapeHTML(address.toString(showAddressSpace))
					: ""));
	}

	/**
	 * Creates a string containing HTML tags to represent the integer number in color.
	 * @param count the integer number
	 * @return the message string containing HTML tags.
	 */
	public static String getNumberString(int count) {
		return colorString(NUMBER_COLOR, Integer.toString(count));
	}

	/**
	 * Creates a string containing HTML tags to represent the text in color for emphasis.
	 * @param text the text to be emphasized.
	 * @return the message string containing HTML tags.
	 */
	public static String getEmphasizeString(String text) {
		return colorString(EMPHASIZE_COLOR, text);
	}

	/**
	 * Creates a string containing HTML tags to represent the offset value in 
	 * color as a hexadecimal value.
	 * @param offset the offset to be displayed in hexadecimal
	 * @return the message string containing HTML tags.
	 */
	public static String getOffsetString(int offset) {
		return colorString(OFFSET_COLOR, DiffUtility.toSignedHexString(offset));
	}

	/**
	 * Creates a string containing HTML tags to represent the hash value in 
	 * color as an unsigned hexadecimal value.
	 * @param hash the hash to be displayed in hexadecimal
	 * @return the message string containing HTML tags.
	 */
	public static String getHashString(long hash) {
		return colorString(NUMBER_COLOR, "0x" + Long.toHexString(hash));
	}
}
