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

import ghidra.util.HelpLocation;

import java.math.BigInteger;

/**
 * Converts byte values to Octal representation.
 */
public class OctalFormatModel implements UniversalDataFormatModel {

	private int symbolSize;
	private static final String GOOD_CHARS = "01234567";

	public OctalFormatModel() {

		symbolSize = 3;
	}

	/**
	 * Get the name of this formatter.
	 */
	public String getName() {
		return "Octal";
	}

	/**
	 * Get the number of bytes to make a unit; in this case, 
	 * returns 1.
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
	 * @return 3 for number of characters in the octal representation.
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

		byte b = block.getByte(index);
		int i = b;
		i &= 0xff; // 0377

		String str = Integer.toOctalString(i);

		if (str.length() > symbolSize) {
			str = str.substring(str.length() - symbolSize);
		}

		return pad(str);

	}

	/**
	 * Returns true to allow values to be changed.
	 */
	public boolean isEditable() {
		return (true);
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

		if (charPosition < 0 || charPosition > 2) {
			return false;
		}
		if (GOOD_CHARS.indexOf(c) == -1) {
			return false;
		}
		// make sure char is valid in the specified position
		if (charPosition == 0 && GOOD_CHARS.indexOf(c) > 3) {
			return false;
		}

		byte b = block.getByte(index);
		char[] charArray = { c };
		byte cb = Byte.parseByte(new String(charArray), 8);

		if (charPosition == 0) {
			b &= 0x3f; // octal 077

			cb <<= 6;
			b += cb;
		}
		else if (charPosition == 1) {
			b &= 0xc7; // octal 307
			cb <<= 3;
			b += cb;
		}
		else {
			b &= 0xf8; // octal 370
			b += cb;
		}

		block.setByte(index, b);
		return true;
	}

	/**
	 * Get number of units in a group. A group may represent
	 * multiple units shown as one entity. This format does not
	 * support groups.
	 */
	public int getGroupSize() {
		return 1;
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
		return 1;
	}

	/**
	 * @see ghidra.app.plugin.core.format.DataFormatModel#validateBytesPerLine(int)
	 */
	public boolean validateBytesPerLine(int bytesPerLine) {
		return true;
	}

	/////////////////////////////////////////////////////////////////
	// *** private methods ***
	/////////////////////////////////////////////////////////////////
	private String pad(String value) {
		StringBuffer sb = new StringBuffer();
		int len = symbolSize - value.length();

		for (int i = 0; i < len; i++) {
			sb.append("0");
		}
		sb.append(value);
		return (sb.toString());
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.format.DataFormatModel#getHelpLocation()
	 */
	public HelpLocation getHelpLocation() {
		return new HelpLocation("ByteViewerPlugin", "Octal");
	}

	public void dispose() {
		// nothing to do
	}
}
