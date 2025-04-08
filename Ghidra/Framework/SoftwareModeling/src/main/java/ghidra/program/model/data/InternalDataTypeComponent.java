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

import org.apache.commons.lang3.StringUtils;

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
	 * Internal method for cleaning up field names. 
	 * @param name the new field name
	 * @return the name with bad chars removed and also set back to null in the event
	 * the new name is the default name.
	 */
	public default String cleanupFieldName(String name) {
		// For now, silently convert whitespace to underscores
		String fieldName = StringUtilities.whitespaceToUnderscores(name);
		if (StringUtils.isBlank(fieldName)) {
			fieldName = null;
		}
		return fieldName;
	}

}
