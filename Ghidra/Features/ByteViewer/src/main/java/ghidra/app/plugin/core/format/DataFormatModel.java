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

import ghidra.app.plugin.core.byteviewer.ByteViewerConfigOptions;
import ghidra.util.HelpLocation;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * NOTE:  ALL DataFormatModel CLASSES MUST END IN "FormatModel".  If not,
 * the ClassSearcher will not find them.
 * 
 * Interface for providing a generic way to display and edit (in
 * various formats) memory.
 */
public interface DataFormatModel extends ExtensionPoint {

	/**
	 * Gets the number of bytes to make a unit, e.g., 
	 * for 'byte' unit size =1, for 'unicode' unit size = 2, etc.
	 */
	int getUnitByteSize();

	/**
	 * Gets data format name.
	 */
	String getName();

	/**
	 * {@return a descriptive name for this data format, used for labels / headers}
	 */
	default String getDescriptiveName() {
		return getName();
	}

	/**
	 * Gets the help location for this format
	 */
	HelpLocation getHelpLocation();

	/**
	 * Gets the number of characters required to display a
	 * unit. For example, an implementation for a Hex formatter
	 * may display a unit as '0xff'. The data unit
	 * size returned would be 4.
	 */
	int getDataUnitSymbolSize();

	/**
	 * Given a character position from 0 to data unit symbol size - 1
	 * it returns a number from 0 to unit byte size - 1 indicating which
	 * byte the character position was obtained from.
	 */
	int getByteOffset(ByteBlock block, int position);

	/**
	 * Given the byte offset into a unit, get the column position.
	 */
	int getColumnPosition(ByteBlock block, int byteOffset);

	/**
	 * Gets the string representation at the given index in the block.
	 * @param block block to change
	 * @param index byte index into the block
	 * @throws ByteBlockAccessException if the block cannot be read
	 * @throws IndexOutOfBoundsException if index is not valid for the
	 * block
	 */
	String getDataRepresentation(ByteBlock block, BigInteger index) throws ByteBlockAccessException;

	default void setByteViewerConfigOptions(ByteViewerConfigOptions options) {
		// default do-nothing
	}

	/**
	 * Returns an error message string if the supplied {@link ByteViewerConfigOptions} are
	 * problematic, otherwise returns null.
	 * 
	 * @param candidateOptions {@link ByteViewerConfigOptions}
	 * @return null if candidate config options are ok, otherwise error message string
	 */
	default String validateByteViewerConfigOptions(ByteViewerConfigOptions candidateOptions) {
		return null;
	}

	/**
	 * Get the number of characters separating units.
	 */
	int getUnitDelimiterSize();

	default void dispose() {
		// do nothing by default
	}

	static String pad(String value, int symbolSize) {
		return pad(value, symbolSize, "0");
	}

	static String pad(String value, int symbolSize, String padChar) {
		return padChar.repeat(Math.max(symbolSize - value.length(), 0)) + value;
	}
}
