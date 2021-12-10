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
import ghidra.program.model.mem.MemBuffer;

/**
 * Array interface
 */
public interface Array extends DataType {

	public static final String ARRAY_LABEL_PREFIX = "ARRAY";

	/**
	 * Returns the number of elements in the array
	 * @return the number of elements in the array
	 */
	int getNumElements();

	/**
	 * Returns the length of an element in the array.  In the case
	 * of a Dynamic base datatype, this element length will have been explicitly specified
	 * at the time of construction.  For a zero-length base type an element length of 1 
	 * will be reported with {@link #getLength()} returning the number of elements.
	 * @return the length of one element in the array.
	 */
	int getElementLength();

	/**
	 * Returns the dataType of the elements in the array.
	 * @return the dataType of the elements in the array
	 */
	DataType getDataType();

	/**
	 * Get the appropriate string to use as the label prefix
	 * for an array, taking into account the actual data at the memory location.
	 * <p>
	 * See also {@link #getDefaultLabelPrefix()}
	 * 
	 * @param buf memory buffer containing the bytes.
	 * @param settings the Settings object
	 * @param len the length of the data.
	 * @param options options for how to format the default label prefix.
	 * @return the label prefix or null if not applicable
	 */
	default public String getArrayDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options) {
		ArrayStringable stringableElementType = ArrayStringable.getArrayStringable(getDataType());
		String prefix = (stringableElementType != null)
				? stringableElementType.getArrayDefaultLabelPrefix(buf, settings, len, options)
				: null;
		return (prefix != null) ? prefix : getDefaultLabelPrefix();
	}

	/**
	 * Get the appropriate string to use as the offcut label prefix for an array, taking into
	 * account the actual data at the memory location.
	 * <p>
	 * See also {@link #getDefaultLabelPrefix()}
	 * 
	 * @param buf memory buffer containing the bytes.
	 * @param settings the Settings object
	 * @param len the length of the data.
	 * @param options options for how to format the default label prefix.
	 * @param offcutLength offcut offset from start of buf
	 * @return the offcut label prefix or null if not applicable
	 */
	default public String getArrayDefaultOffcutLabelPrefix(MemBuffer buf, Settings settings,
			int len, DataTypeDisplayOptions options, int offcutLength) {

		ArrayStringable stringableElementType = ArrayStringable.getArrayStringable(getDataType());
		String prefix = (stringableElementType != null)
				? stringableElementType.getArrayDefaultOffcutLabelPrefix(buf, settings, len,
					options, offcutLength)
				: null;
		return (prefix != null) ? prefix : getDefaultLabelPrefix(buf, settings, len, options);
	}

	/**
	 * Get the representation which corresponds to an array in memory.  This will either be a
	 * String for the ArrayStringable case, "??" for uninitialized data,
	 * or the empty string if it is not.
	 * 
	 * @param buf data buffer
	 * @param settings data settings
	 * @param length length of array
	 * @return a String if it is an array of chars; otherwise empty string, never null.
	 */
	default public String getArrayRepresentation(MemBuffer buf, Settings settings, int length) {
		if (getNumElements() == 0) {
			return "";
		}
		if (!buf.isInitializedMemory()) {
			return StringDataInstance.UNKNOWN;
		}
		ArrayStringable stringableElementType = ArrayStringable.getArrayStringable(getDataType());
		String value =
			(stringableElementType != null && stringableElementType.hasStringValue(settings))
					? new StringDataInstance(stringableElementType, settings, buf, length,
						true).getStringRepresentation()
					: null;
		return (value != null) ? value : "";
	}

	/**
	 * Get the value object which corresponds to an array in memory.  This will either be a
	 * String for the ArrayStringable case or null.
	 * 
	 * @param buf data buffer
	 * @param settings data settings
	 * @param length length of array
	 * @return a String if it is an array of chars; otherwise null.
	 */
	default Object getArrayValue(MemBuffer buf, Settings settings, int length) {
		if (!buf.getMemory().getAllInitializedAddressSet().contains(buf.getAddress())) {
			return null;
		}
		ArrayStringable as = ArrayStringable.getArrayStringable(getDataType());
		Object value = (as != null) ? as.getArrayString(buf, settings, length) : null;

		return value;
		// TODO
		// For large array it is not scalable to create a java array object.  Perhaps
		// we could create a GhidraArray that can dish out objects.
//			DataType dt = arrayDt.getDataType();
//			Class<?> valueClass = dt.getValueClass(settings);
//			if (valueClass != null) {
//				int count = arrayDt.getNumElements();
//				int elementLength = arrayDt.getElementLength();
//				WrappedMemBuffer wrappedBuffer = new WrappedMemBuffer(buf, 0);
//				Object[] array = (Object[]) java.lang.reflect.Array.newInstance(valueClass, count);
//				for (int i = 0; i < count; i++) {
//					wrappedBuffer.setBaseOffset(i * elementLength);
//					array[i] = dt.getValue(wrappedBuffer, settings, elementLength);
//				}
//				return array;
//			}
	}

	/**
	 * Get the value Class of a specific arrayDt with settings
	 * ( see {@link #getArrayValueClass(Settings)} ).
	 * 
	 * @param settings the relevant settings to use or null for default.
	 * @return Class of the value to be returned by the array or null if it can vary
	 * or is unspecified (String or Array class will be returned).
	 */
	default public Class<?> getArrayValueClass(Settings settings) {
		DataType dt = getDataType();
		if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}
		if (dt instanceof ArrayStringable) {
			if (((ArrayStringable) dt).hasStringValue(settings)) {
				return String.class;
			}
		}
		Class<?> valueClass = dt.getValueClass(settings);
		return valueClass != null ? Array.class : null;
	}

}
