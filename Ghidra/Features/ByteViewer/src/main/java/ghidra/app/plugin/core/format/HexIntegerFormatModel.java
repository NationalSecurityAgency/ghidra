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
 * Converts byte values to Integer represented as an 8 digit hex number.
 */
public class HexIntegerFormatModel implements UniversalDataFormatModel {

	private int symbolSize;

	public HexIntegerFormatModel() {

		symbolSize = 8;
	}

	/**
	 * Get the name of this formatter.
	 */
	public String getName() {
		return "HexInteger";
	}

	/**
	 * Get the number of bytes to make a unit; in this case, 
	 * returns 4.
	 */
	public int getUnitByteSize() {
		return 4;
	}

	/**
	 * Returns the byte used to generate the character at a given
	 * position.
	 * @param position number in the range 0 to 7
	 */
	public int getByteOffset(ByteBlock block, int position) {

		int o = position / 2;

		if (block.isBigEndian()) {
			return o;
		}
		return 3 - o;
	}

	/**
	 * Given the byte offset into a unit, get the column position.
	 */
	public int getColumnPosition(ByteBlock block, int byteOffset) {
		if (byteOffset > 3) {
			throw new IllegalArgumentException("invalid byteOffset: " + byteOffset);
		}
		if (block.isBigEndian()) {
			return byteOffset * 2;
		}
		return (3 - byteOffset) * 2;
	}

	/**
	 * Gets the number of characters required to display a
	 * unit. 
	 * @return 4 for number of characters in the integer representation.
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

		int i = block.getInt(index);

		String str = Integer.toHexString(i);

		return pad(str);

	}

	/**
	 * Returns true to allow values to be changed.
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

		if (charPosition < 0 || charPosition > symbolSize - 1) {
			return false;
		}
		char[] charArray = { c };
		String s = new String(charArray);
		try {
			Integer.parseInt(s, 16);
		}
		catch (Exception e) {
			return false;
		}

		byte cb = Byte.parseByte(new String(charArray), 16);
		// get the correct byte offset based on position
		int byteOffset = getByteOffset(block, charPosition);
		BigInteger saveIndex = index;
		index = index.add(BigInteger.valueOf(byteOffset));
		byte b = block.getByte(index);
		b = adjustByte(b, cb, charPosition);
		int intValue = getInt(block, saveIndex, b, byteOffset);
		block.setInt(saveIndex, intValue);
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
		return bytesPerLine % 4 == 0;
	}

	/////////////////////////////////////////////////////////////////
	// *** private methods ***
	/////////////////////////////////////////////////////////////////
	/**
	 * Returns value with leading zeros.
	 */
	private String pad(String value) {
		StringBuffer sb = new StringBuffer();
		int len = symbolSize - value.length();

		for (int i = 0; i < len; i++) {
			sb.append("0");
		}
		sb.append(value);
		return sb.toString();
	}

	/**
	 * adjust byte b to use either the upper 4 bits or
	 * the lower 4 bits of newb according to charPosition.
	 */
	private byte adjustByte(byte b, byte newb, int charPosition) {
		if (charPosition % 2 == 0) {
			// its the high order byte
			b &= 0x0f;
			newb <<= 4;
		}
		else {
			b &= 0xf0;
		}
		b += newb;
		return b;
	}

	private int getInt(ByteBlock block, BigInteger offset, byte newb, int byteOffset) {
		byte[] b = new byte[4];
		try {
			for (int i = 0; i < b.length; i++) {
				b[i] = block.getByte(offset.add(BigInteger.valueOf(i)));
			}
			b[byteOffset] = newb;

			if (block.isBigEndian()) {
				return (b[0] << 24) | ((b[1] << 16) & 0x00FF0000) | ((b[2] << 8) & 0x0000FF00) |
					(b[3] & 0x000000FF);
			}
			return (b[3] << 24) | ((b[2] << 16) & 0x00FF0000) | ((b[1] << 8) & 0x0000FF00) |
				(b[0] & 0x000000FF);

		}
		catch (ByteBlockAccessException e) {
		}
		return 0;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.format.DataFormatModel#getHelpLocation()
	 */
	public HelpLocation getHelpLocation() {
		return new HelpLocation("ByteViewerPlugin", "HexInteger");
	}

	public void dispose() {
	}

}
