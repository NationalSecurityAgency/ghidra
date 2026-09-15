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
package ghidra.app.plugin.core.format;

import java.math.BigInteger;

import ghidra.util.HelpLocation;

/**
 * Converts byte values to Integer representation in decimal format.
 * This formatter does not allow editing.
 */
public class IntegerFormatModel implements UniversalDataFormatModel {

	private int symbolSize;

	public IntegerFormatModel() {
		this.symbolSize = 11; // 1 char for sign
	}

	/**
	 * Get the name of this formatter.
	 */
	@Override
	public String getName() {
		return "Integer";
	}

	/**
	 * Get the number of bytes to make a unit; in this case, 
	 * returns 4.
	 */
	@Override
	public int getUnitByteSize() {
		return 4;
	}

	/**
	 * Given a character position from 0 to data unit symbol size - 1
	 * it returns a number from 0 to unit byte size - 1 indicating which
	 * byte the character position was obtained from.
	 */
	@Override
	public int getByteOffset(ByteBlock block, int position) {

		return 0;
	}

	/**
	 * Given the byte offset into a unit, get the column position.
	 */
	@Override
	public int getColumnPosition(ByteBlock block, int byteOffset) {
		return 0;
	}

	/**
	 * Gets the number of characters required to display a
	 * unit. 
	 * @return 4 for number of characters in the integer representation.
	 */
	@Override
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
	@Override
	public String getDataRepresentation(ByteBlock block, BigInteger index)
			throws ByteBlockAccessException {

		// determine what bytes to get
		int i = block.getInt(index);

		return DataFormatModel.pad(Integer.toString(i), symbolSize, " ");

	}

	/**
	 * Get the number of characters separating units.
	 */
	@Override
	public int getUnitDelimiterSize() {
		return 1;
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation("ByteViewerPlugin", "Integer");
	}
}
