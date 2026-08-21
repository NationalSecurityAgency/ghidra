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

import ghidra.util.StringUtilities;

public interface InternalDataTypeComponent extends DataTypeComponent {

	/**
	 * Sets the DataType for this component.  Must be used carefully since the component
	 * will not be resized.
	 * @param dataType the new DataType for this component
	 */
	public void setDataType(DataType dataType);

	/**
	 * Update component ordinal, offset and length during alignment
	 * @param ordinal updated ordinal
	 * @param offset updated offset
	 * @param length updated byte length
	 */
	void update(int ordinal, int offset, int length);

	public static String toString(DataTypeComponent c) {
		StringBuffer buffer = new StringBuffer();
		buffer.append("  " + c.getOrdinal());
		buffer.append("  " + c.getOffset());
		buffer.append("  " + c.getDataType().getName());
		if (c.isBitFieldComponent()) {
			buffer.append("(" + ((BitFieldDataType) c.getDataType()).getBitOffset() + ")");
		}
		buffer.append("  " + c.getLength());
		String name = c.getFieldName();
		if (name == null) {
			name = "";
		}
		buffer.append("  " + name);
		String cmt = c.getComment();
		buffer.append("  " + ((cmt != null) ? ("\"" + cmt + "\"") : ""));
		return buffer.toString();
	}

	/**
	 * Modify field name to transform whitespace chars to underscores after triming and checking
	 * for empty string.  Empty string is returned as null for storage to indicate default name use. 
	 * @param name original field name (may be null) 
	 * @return revised field name (may be null)
	 */
	public static String cleanupFieldName(String name) {
		String fieldName = name;
		if (name != null) {

			// Trim field name and ensure empty string is stored as null to indicate default field name
			fieldName = name.trim();

			if (fieldName.length() == 0) {
				fieldName = null;
			}
			else {
				// NOTE: Should we be checking for default field name pattern and disallow.
				// If so, additional parameters would be required (e.g., struct vs union, is packed struct)

				// Don't allow whitespace in field names. Until we change the API to throw an exception
				// when a field name has whitespace, just silently replace whitespace with underscores.
				fieldName = StringUtilities.whitespaceToUnderscores(fieldName);
			}
		}
		return fieldName;
	}

}
