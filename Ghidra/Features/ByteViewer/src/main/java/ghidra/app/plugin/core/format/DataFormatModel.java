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
import ghidra.util.classfinder.ExtensionPoint;

import java.math.BigInteger;

/**
 * NOTE:  ALL DataFormatModel CLASSES MUST END IN "FormatModel".  If not,
 * the ClassSearcher will not find them.
 * 
 * Interface for providing a generic way to display and edit (in
 * various formats) memory.
 */
public interface DataFormatModel extends ExtensionPoint {

	public static final int NEXT_UNIT = -1;
	public static final int PREVIOUS_UNIT = -1;

	/**
	 * Gets the number of bytes to make a unit, e.g., 
	 * for 'byte' unit size =1, for 'unicode' unit size = 2, etc.
	 */
	public int getUnitByteSize();

	/**
	 * Gets data format name.
	 */
	public String getName();

	/**
	 * Gets the help location for this format
	 */
	public HelpLocation getHelpLocation();

	/**
	 * Gets the number of characters required to display a
	 * unit. For example, an implementation for a Hex formatter
	 * may display a unit as '0xff'. The data unit
	 * size returned would be 4.
	 */
	public int getDataUnitSymbolSize();

	/**
	 * Given a character position from 0 to data unit symbol size - 1
	 * it returns a number from 0 to unit byte size - 1 indicating which
	 * byte the character position was obtained from.
	 */
	public int getByteOffset(ByteBlock block, int position);

	/**
	 * Given the byte offset into a unit, get the column position.
	 */
	public int getColumnPosition(ByteBlock block, int byteOffset);

	/**
	 * Gets the string representation at the given index in the block.
	 * @param block block to change
	 * @param index byte index into the block
	 * @throws ByteBlockAccessException if the block cannot be read
	 * @throws IndexOutOfBoundsException if index is not valid for the
	 * block
	 */
	public String getDataRepresentation(ByteBlock block, BigInteger index)
			throws ByteBlockAccessException;

	/**
	 * Returns true if the formatter allows values to be changed.
	 */
	public boolean isEditable();

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
			throws ByteBlockAccessException;

	/**
	 * Get number of units in a group. A group may represent
	 * multiple units shown as one entity.
	 */
	public int getGroupSize();

	/**
	 * Set the number of units in a group.
	 * @throws UnsupportedOperationException if model does not
	 * support groups
	 */
	public void setGroupSize(int groupSize);

	/**
	 * Get the number of characters separating units.
	 */
	public int getUnitDelimiterSize();

	/**
	 * Verify that this model can support the given bytes per line
	 * value.
	 * @return true if this model supports the given number of bytes per line
	 */
	public boolean validateBytesPerLine(int bytesPerLine);

	public void dispose();

}
