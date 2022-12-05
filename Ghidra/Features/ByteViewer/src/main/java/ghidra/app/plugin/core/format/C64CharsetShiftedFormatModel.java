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
package ghidra.app.plugin.core.format;

import ghidra.app.plugin.core.byteviewer.ByteViewerComponentProvider;
import ghidra.util.HelpLocation;

import java.math.BigInteger;
import java.util.Arrays;


/**
 * Converts byte values to Ascii representation.
 */

 public class C64CharsetShiftedFormatModel implements UniversalDataFormatModel {

	private int symbolSize;

	public C64CharsetShiftedFormatModel () {
		symbolSize = 1;
	}

	/**
	 * Get the name of this formatter.
	 */
	public String getName() {
		return "C64 Charset Shifted";
	}

	/**
	 * Get the number of bytes to make a unit; in this case it
	 * takes 1 byte to make an Ascii value.
	 */
	public int getUnitByteSize() {
		return 1;
	}

	/**
	 * Given a character position from 0 to data unit symbol size - 1
	 * it returns a number from 0 to unit byte size - 1 indicating which
	 * byte the character position was obtained from.
	 */
	public int getByteOffset(ByteBlock block, int position) {
		return 0;
	}

	/**
	 * Given the byte offset into a unit, get the column position.
	 */
	public int getColumnPosition(ByteBlock block, int byteOffset) {
		return 0;
	}

	/**
	 * Gets the number of characters required to display a
	 * unit.
	 */
	public int getDataUnitSymbolSize() {
		return symbolSize;
	}

	/**
	 * Gets the string representation at the given index in the block.
	 * @param block block to change
	 * @param index byte index into the block
	 * @throws ByteBlockAccessException if the block cannot be read
	 * @throws IndexOutOfBoundsException if index is not valid for the
	 * block
	 */
	public String getDataRepresentation(ByteBlock block, BigInteger index)
			throws ByteBlockAccessException {
// Unicode13 Mappings for Retro Computing
			String[] Petscii = {
// First 128 characters are found in Unicode, mapping them accordingly
				"@", "A", "B", "C", "D", "E", "F", "G",
				"H", "I", "J", "K", "L", "M", "N", "O",
				"P", "Q", "R", "S", "T", "U", "V", "W",
				"X", "Y", "Z", "[", "£", "]", "\u2191", "\u2190",
				" ", "!", "\"", "#", "$", "%", "&", "'",
				"(", ")", "*", "+", ",", "-", ".", "/",
				"0", "1", "2", "3", "4", "5", "6", "7",
				"8", "9", ":", ";", "<", "=", ">", "?",
				"\uD83E\uDF79", "\u2660", "\uD83E\uDF72", "\uD83E\uDF78", "\uD83E\uDF77", "\uD83E\uDF76", "\uD83E\uDF7A", "\uD83E\uDF71",
				"\uD83E\uDF74", "\u256E", "\u2570", "\u256F", "\uD83E\uDF7C", "\u2572", "\u2571", "\uD83E\uDF7D",
				"\uD83E\uDF7E", "\u25CF", "\uD83E\uDF7B", "\u2665", "\uD83E\uDF70", "\u256D", "\u2573", "\u25CB",
				"\u2663", "\uD83E\uDF75", "\u2666", "\u253C", "\uD83E\uDF8C", "\u2502", "\u03C0", "\u25E5",
				"\u00A0", "\u258C", "\u2584", "\u2594", "\u2581", "\u258F", "\u2592", "\u2495",
				"\uD83E\uDF8F", "\u25E4", "\uD83E\uDF87", "\u251C", "\u2597", "\u2514", "\u2510", "\u2582",
				"\u250C", "\u2534", "\u252C", "\u2524", "\u258E", "\u258D", "\uD83E\uDF88", "\uD83E\uDF82",
				"\uD83E\uDF83", "\u2583", "\uD83E\uDF7F", "\u2596", "\u259D", "\u2518", "\u2598", "\u259A",
// Inverted characters that follow cannot be found in Unicode, map for the C64 Pro Mono font.
			"\uEF80", "\uEF81", "\uEF82", "\uEF83", "\uEF84", "\uEF85", "\uEF86", "\uEF87", 
			"\uEF88", "\uEF89", "\uEF8A", "\uEF8B", "\uEF8C", "\uEF8D", "\uEF8E", "\uEF8F", 
			"\uEF90", "\uEF91", "\uEF92", "\uEF93", "\uEF94", "\uEF95", "\uEF96", "\uEF97", 
			"\uEF98", "\uEF99", "\uEF9A", "\uEF9B", "\uEF9C", "\uEF9D", "\uEF9E", "\uEF9F", 
			"\uEFA0", "\uEFA1", "\uEFA2", "\uEFA3", "\uEFA4", "\uEFA5", "\uEFA6", "\uEFA7", 
			"\uEFA8", "\uEFA9", "\uEFAA", "\uEFAB", "\uEFAC", "\uEFAD", "\uEFAE", "\uEFAF", 
			"\uEFB0", "\uEFB1", "\uEFB2", "\uEFB3", "\uEFB4", "\uEFB5", "\uEFB6", "\uEFB7", 
			"\uEFB8", "\uEFB9", "\uEFBA", "\uEFBB", "\uEFBC", "\uEFBD", "\uEFBE", "\uEFBF", 
			"\uEFC0", "\uEFC1", "\uEFC2", "\uEFC3", "\uEFC4", "\uEFC5", "\uEFC6", "\uEFC7", 
			"\uEFC8", "\uEFC9", "\uEFCA", "\uEFCB", "\uEFCC", "\uEFCD", "\uEFCE", "\uEFCF", 
			"\uEFD0", "\uEFD1", "\uEFD2", "\uEFD3", "\uEFD4", "\uEFD5", "\uEFD6", "\uEFD7", 
			"\uEFD8", "\uEFD9", "\uEFDA", "\uEFDB", "\uEFDC", "\uEFDD", "\uEFDE", "\uEFDF", 
			"\uEFE0", "\uEFE1", "\uEFE2", "\uEFE3", "\uEFE4", "\uEFE5", "\uEFE6", "\uEFE7", 
			"\uEFE8", "\uEFE9", "\uEFEA", "\uEFEB", "\uEFEC", "\uEFED", "\uEFEE", "\uEFEF", 
			"\uEFF0", "\uEFF1", "\uEFF2", "\uEFF3", "\uEFF4", "\uEFF5", "\uEFF6", "\uEFF7", 
			"\uEFF8", "\uEFF9", "\uEFFA", "\uEFFB", "\uEFFC", "\uEFFD", "\uEFFE", "\uEFFF"
		};

		byte b = block.getByte(index);
		String str = null;
		str = Petscii[(b & 0xFF)];
		return str;
	}

	/**
	 * Returns true if the formatter allows values to be changed.
	 */
	public boolean isEditable() {
		return true;
	}

	/**
	 * Overwrite a value in a ByteBlock.
	 * @param block block to change
	 * @param index byte index into the block
	 * @param pos The position within the unit where c will be the
	 * new character.
	 * @param c new character to put at pos param
	 * @return true if the replacement is legal, false if the
	 * replacement value would not make sense for this format, e.g.
	 * attempt to put a 'z' in a hex unit.
	 * @throws ByteBlockAccessException if the block cannot be updated
	 * @throws IndexOutOfBoundsException if index is not valid for the
	 * block
	 */
	public boolean replaceValue(ByteBlock block, BigInteger index, int charPosition, char c)
			throws ByteBlockAccessException {

		if (charPosition != 0) {
			return false;
		}

		block.getByte(index);
		byte cb = (byte) c;

		if (cb < 0x20 || cb == 0x7f) {
			return false;
		}

		block.setByte(index, cb);
		return true;
	}

	/**
	 * Get number of units in a group. A group may represent
	 * multiple units shown as one entity. This format does not
	 * support groups.
	 * @throws UnsupportedOperationException 
	 */
	public int getGroupSize() {
		return 0;
	}

	/**
	 * Set the number of units in a group. This format does not
	 * support groups.
	 * @throws UnsupportedOperationException 
	 */
	public void setGroupSize(int groupSize) {
		throw new UnsupportedOperationException("groups are not supported");
	}

	/**
	 * Get the number of characters separating units.
	 */
	public int getUnitDelimiterSize() {
		return 0;
	}

	/**
	 * @see ghidra.app.plugin.core.format.DataFormatModel#validateBytesPerLine(int)
	 */
	public boolean validateBytesPerLine(int bytesPerLine) {
		return true;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.format.DataFormatModel#getHelpLocation()
	 */
	public HelpLocation getHelpLocation() {
		return new HelpLocation("ByteViewerPlugin", "Petscii");
	}

	public void dispose() {
	}

	public boolean supportsProvider(ByteViewerComponentProvider provider) {
		return true;
	}
}
