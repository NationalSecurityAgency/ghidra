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
 * Converts byte values to hex representation.
 */
public class HexFormatModel implements UniversalDataFormatModel {

	public final static String NAME = "Hex";

	private int symbolSize;
	private int unitByteSize;
	private boolean prefixEnabled;
	private boolean alphaCapsEnabled;
	private int groupSize = 1;

	private static final String GOOD_CHARS = "0123456789abcdefABCDEF";

	public HexFormatModel() {
		this.prefixEnabled = false;
		this.alphaCapsEnabled = false;
		unitByteSize = groupSize;
		if (prefixEnabled) {
			symbolSize = 4 * groupSize; // there are 2 chars per byte of data
		}
		else {
			symbolSize = 2 * groupSize; // there are 2 chars per byte of data
		}
	}

	/**
	 * Get the name of this formatter.
	 */
	public String getName() {
		return NAME;
	}

	/**
	 * Get the number of bytes to make a unit; in this case, 
	 * returns 1.
	 */
	public int getUnitByteSize() {
		return unitByteSize;
	}

	/**
	 * Gets the number of characters required to display a
	 * unit. 
	 * @return 2 for number of characters in a unit
	 */
	public int getDataUnitSymbolSize() {
		return symbolSize;
	}

	/**
	 * Get number of units in a group.
	 */
	public int getGroupSize() {
		return groupSize;
	}

	/**
	 * Set the number of units in a group.
	 */
	public void setGroupSize(int groupSize) {
		this.groupSize = groupSize;
		unitByteSize = groupSize;
		symbolSize = (2 * groupSize);
	}

	/**
	 * Should this model display spaces by groupSize?
	 */
	public boolean isSpaceByGroupSize() {
		return false;
	}

	/**
	 * Returns the byte used to generate the character at a given
	 * position.
	 */
	public int getByteOffset(ByteBlock block, int pos) {
		if (prefixEnabled) {
			if (pos <= 3) {
				return 0;
			}
			else if (pos < (2 + unitByteSize * 2)) {
				return ((pos - 2) / 2);
			}
			return unitByteSize - 1;
		}
		if (pos < unitByteSize * 2) {
			return (pos / 2);
		}
		return unitByteSize - 1;
	}

	/**
	 * Given the byte offset into a unit, get the column position.
	 */
	public int getColumnPosition(ByteBlock block, int byteOffset) {
		if (prefixEnabled) {
			return byteOffset * 2 + 2;
		}
		return byteOffset * 2;
	}

	/**
	 * Gets the position where the cursor should be placed in
	 * order to do an 'overwrite' of data.
	 * @param position current position of the cursor within
	 * the data unit.
	 */
	public int getInsertionPosition(int pos) {
		if (prefixEnabled) {
			if (pos <= 2) {
				return 2;
			}
			else if (pos < symbolSize) {
				return pos;
			}
			else {
				return symbolSize - 1;
			}
		}
		if (pos <= 0) {
			return 0;
		}
		else if (pos < symbolSize) {
			return pos;
		}
		else {
			return symbolSize - 1;
		}
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

		StringBuffer sb = new StringBuffer();
		//System.out.println("representation: = " + block.getLocationRepresentation(index)+ ", index = " + index);
		if (prefixEnabled) {
			sb.append("0x");
		}

		StringBuffer strBuff = new StringBuffer();
		BigInteger byteIndex = index;
		boolean qflag = false;
		for (int idx = 0; idx < unitByteSize; idx++) {
			try {
				byte b = block.getByte(byteIndex);
				strBuff.append(adjust(Integer.toHexString(b)));
				byteIndex = byteIndex.add(BigInteger.ONE);
			}
			catch (ByteBlockAccessException bbae) {
				if (idx == 0 || qflag) {
					strBuff.append("??");
					qflag = true;
				}
			}
		}

		String str = strBuff.toString();

		if (alphaCapsEnabled) {
			str = str.toUpperCase();
		}
		sb.append(str);
		return new String(sb);
	}

	/**
	 * Gets the string representation for numUnits at the given
	 * index in the block.
	 * @param block block to change
	 * @param index byte index into the block
	 * @param numUnits number of units to get
	 * @throws ByteBlockAccessException if the block cannot be read
	 * @throws IndexOutOfBoundsException if index is not valid for the
	 * block
	 */
	public String getDataRepresentation(ByteBlock block, BigInteger index, int numUnits)
			throws ByteBlockAccessException {

		int n;
		StringBuffer sb = new StringBuffer();

		System.out.println("representation: = " + block.getLocationRepresentation(index) +
			", index = " + index);
		for (n = 0; n < numUnits; n++, index = index.add(BigInteger.ONE)) {
			String str = getDataRepresentation(block, index);

			sb.append(str);

		}

		return new String(sb);
	}

	/**
	 * Returns true to allow values to be changed.
	 */
	public boolean isEditable() {
		return true;
	}

	/**
	 * Get the number of characters separating units for display purposes.
	 */
	public int getUnitDelimiterSize() {
		return 1;
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

		if (GOOD_CHARS.indexOf(c) == -1) {
			return false;
		}
		if ((prefixEnabled && (charPosition < 2 || charPosition >= symbolSize)) ||
			(!prefixEnabled && (charPosition < 0 || charPosition >= symbolSize))) {
			return false;
		}

		int byteNo = getByteOffset(block, charPosition);
		index = index.add(BigInteger.valueOf(byteNo));

		byte b = block.getByte(index);
		char[] charArray = { c };
		byte cb = Byte.parseByte(new String(charArray), 16);

		if (charPosition % 2 == 0) {
			// its the high order byte
			b &= 0x0f;
			cb <<= 4;
			b += cb;
		}
		else {
			b &= 0xf0;
			b += cb;
		}
		block.setByte(index, b);
		return true;
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
	private String adjust(String value) {
		StringBuffer sb = new StringBuffer();
		int strLen = value.length();

		if (strLen > 2) {
			sb.append(value.substring(strLen - 2));
		}
		else {
			int len = 2 - strLen;

			for (int i = 0; i < len; i++) {
				sb.append("0");
			}
			sb.append(value);
		}
		return (sb.toString());
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.format.DataFormatModel#getHelpLocation()
	 */
	public HelpLocation getHelpLocation() {
		return new HelpLocation("ByteViewerPlugin", "Hex");
	}

	public void dispose() {
	}

}
