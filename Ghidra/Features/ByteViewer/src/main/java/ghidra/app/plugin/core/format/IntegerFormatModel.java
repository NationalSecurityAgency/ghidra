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
 * Converts byte values to Integer representation in decimal format.
 * This formatter does not allow editing.
 */
public class IntegerFormatModel implements UniversalDataFormatModel {

	private int symbolSize;

	public IntegerFormatModel() {

		symbolSize = 11; // 1 char for sign
	}

	/**
	 * Get the name of this formatter.
	 */
	public String getName() {
		return "Integer";
	}

	/**
	 * Get the number of bytes to make a unit; in this case, 
	 * returns 4.
	 */
	public int getUnitByteSize() {
		return 4;
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

		// determine what bytes to get
		int i = block.getInt(index);

		String str = Integer.toString(i);

		return pad(str);

	}

	/**
	 * Returns false to allow no values to be changed.
	 */
	public boolean isEditable() {
		return false;
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
	public boolean replaceValue(ByteBlock block, BigInteger index, int pos, char c)
			throws ByteBlockAccessException {

		return false;
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
	 * Returns value with leading zeros if the value
	 * represents a positive number; returns value
	 * with leading blanks if the value represents a
	 * negative number.
	 */
	private String pad(String value) {
		StringBuffer sb = new StringBuffer();
		int len = symbolSize - value.length();

		for (int i = 0; i < len; i++) {
			sb.append(" ");
		}
		sb.append(value);
		return (sb.toString());
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.format.DataFormatModel#getHelpLocation()
	 */
	public HelpLocation getHelpLocation() {
		return new HelpLocation("ByteViewerPlugin", "Integer");
	}

	public void dispose() {
		// nothing to do
	}

}
