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
package ghidra.program.model.data;

import ghidra.docking.settings.Settings;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemBuffer;

/**
 * <code>ArrayStringable</code> identifies those data types which when formed into
 * an array can be interpreted as a string (e.g., character array).  The {@link Array}
 * implementations will leverage this interface as both a marker and to generate appropriate
 * representations and values for data instances.
 */
public interface ArrayStringable extends DataType {

	/**
	 * For cases where an array of this type exists, determines if a String value
	 * will be returned.
	 * <p>
	 * @param settings
	 * @return true if array of this type with the specified settings will return
	 * a String value.
	 */
	public boolean hasStringValue(Settings settings);

	/**
	 * Returns a {@link StringDataInstance} representing this ArrayStringable's contents.
	 *
	 * <p>
	 * @param buf {@link MemBuffer} containing the data bytes.
	 * @param settings {@link Settings} object containing settings, usually the {@link Data}
	 * element.
	 * @param length number of bytes that this data object contains (ie. how big was the array)
	 * @return a new {@link StringDataInstance} representing this ArrayStringable's contents,
	 * never NULL.  See {@link StringDataInstance#NULL_INSTANCE}.
	 */
	public default StringDataInstance getStringDataInstance(MemBuffer buf, Settings settings,
			int length) {
		return hasStringValue(settings) ? new StringDataInstance(this, settings, buf, length)
				: StringDataInstance.NULL_INSTANCE;
	}

	/**
	 * For cases where an array of this type exists, get the array value as a String.
	 * When data corresponds to character data it should generally be expressed as a string.
	 * A null value is returned if not supported or memory is uninitialized.
	 * @param buf data buffer
	 * @param settings data settings
	 * @param length length of array
	 * @return array value expressed as a string or null if data is not character data
	 */
	public default String getArrayString(MemBuffer buf, Settings settings, int length) {
		return getStringDataInstance(buf, settings, length).getStringValue();
	}

	/**
	 * For cases where an array of this type exists, get the representation string which
	 * corresponds to the array (example: String for an array of chars).
	 * @param buf memory buffer containing the bytes.
	 * @param settings the Settings object
	 * @param length the length of the data.
	 * @return array representation or null of an array representation is not supported.
	 */
	public default String getArrayRepresentation(MemBuffer buf, Settings settings, int length) {
		return getStringDataInstance(buf, settings, length).getStringRepresentation();
	}

	/**
	 * For cases where an array of this type exists, get the appropriate string to use as the
	 * default label prefix for the array.
	 * @param buf memory buffer containing the bytes.
	 * @param settings the Settings object
	 * @param length the length of the data.
	 * @param options options for how to format the default label prefix.
	 * @return the default label prefix or null if none specified.
	 */
	public String getArrayDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options);

	/**
	 * For cases where an array of this type exists, get the appropriate string to use as the
	 * default label prefix, taking into account the fact that there exists a reference to the
	 * data that references <tt>offcutLength</tt> bytes into this type
	 *
	 * @param buf memory buffer containing the bytes.
	 * @param settings the Settings object
	 * @param length the length of the data.
	 * @param options options for how to format the default label prefix.
	 * @param offcutOffset
	 * @return the default label prefix or null if none specified.
	 */
	public String getArrayDefaultOffcutLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options, int offcutLength);

	// ----------------------------------------------------------------------------
	//
	// Utility methods
	//
	// ----------------------------------------------------------------------------

	/**
	 * Get the ArrayStringable for a specified data type. Not used on an Array DataType, but
	 * on Array's element's type.
	 * <p>
	 * @param dt data type
	 * @return ArrayStringable object, or null.
	 */
	public static ArrayStringable getArrayStringable(DataType dt) {
		if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}
		return (dt instanceof ArrayStringable) ? (ArrayStringable) dt : null;
	}

	/**
	 * Get the appropriate string to use as the label prefix
	 * for an array which corresponds to an ArrayStringable
	 * element data type.
	 * @param arrayDt array data type
	 * @param buf memory buffer containing the bytes.
	 * @param settings the Settings object
	 * @param length the length of the data.
	 * @param options options for how to format the default label prefix.
	 * @return the ArrayStringable label prefix or null if not applicable
	 */
	public static String getArrayStringableLabelPrefix(Array arrayDt, MemBuffer buf,
			Settings settings, int len, DataTypeDisplayOptions options) {
		ArrayStringable as = getArrayStringable(arrayDt.getDataType());
		return (as != null) ? as.getArrayDefaultLabelPrefix(buf, settings, len, options) : null;
	}

	/**
	 * Get the appropriate string to use as the offcut label prefix
	 * for an array which corresponds to an ArrayStringable
	 * element data type.
	 * @param arrayDt array data type
	 * @param buf memory buffer containing the bytes.
	 * @param settings the Settings object
	 * @param length the length of the data.
	 * @param options options for how to format the default label prefix.
	 * @param offcutLength offcut offset from start of buf
	 * @return the ArrayStringable offcut label prefix or null if not applicable
	 */
	public static String getArrayStringableOffcutLabelPrefix(Array arrayDt, MemBuffer buf,
			Settings settings, int len, DataTypeDisplayOptions options, int offcutLength) {
		ArrayStringable as = getArrayStringable(arrayDt.getDataType());
		return (as != null)
				? as.getArrayDefaultOffcutLabelPrefix(buf, settings, len, options, offcutLength)
				: null;
	}
}
