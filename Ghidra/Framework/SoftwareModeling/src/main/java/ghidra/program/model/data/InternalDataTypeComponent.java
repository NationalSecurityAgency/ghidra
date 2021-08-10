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
		buffer.append("  " + c.getFieldName());
		String cmt = c.getComment();
		buffer.append("  " + ((cmt != null) ? ("\"" + cmt + "\"") : cmt));
		return buffer.toString();
	}

}
