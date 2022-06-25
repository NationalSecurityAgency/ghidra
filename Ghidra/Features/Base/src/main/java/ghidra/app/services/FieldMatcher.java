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
package ghidra.app.services;

import java.util.Objects;

import ghidra.program.model.data.*;
import ghidra.util.datastruct.SortedRangeList;

/**
 * This class allows clients to match on multiple field attributes, such as name and offset
 * within a parent data type.
 * <p>
 * Use {@link #FieldMatcher(DataType)} as an 'empty' or 'ignored' field matcher to signal that any
 * field match is considered value.
 */
public class FieldMatcher {

	private String fieldName;
	private SortedRangeList fieldOffsets = new SortedRangeList();
	private DataType dataType;

	/**
	 * Creates an 'empty' matcher that can be used to signal no specific field or offset match
	 * is required.
	 * @param dataType the non-null data type.
	 */
	public FieldMatcher(DataType dataType) {
		this.dataType = Objects.requireNonNull(dataType);
	}

	public FieldMatcher(DataType dataType, String fieldName) {
		this.dataType = Objects.requireNonNull(dataType);
		this.fieldName = fieldName;
	}

	public FieldMatcher(DataType dataType, int offset) {
		this.dataType = Objects.requireNonNull(dataType);
		fieldOffsets.addRange(offset, offset);
	}

	/**
	 * Signals that no specific field match is required.
	 * @return true if no field or offset has been specified.
	 */
	public boolean isIgnored() {
		return fieldName == null && fieldOffsets.isEmpty();
	}

	public boolean matches(String dtFieldName, int dtOffset) {

		if (isIgnored()) {
			return true; // an empty matcher signals to match all fields
		}

		if (fieldName != null) {
			if (Objects.equals(fieldName, dtFieldName)) {
				return true;
			}
		}

		if (fieldOffsets.contains(dtOffset)) {
			return true;
		}

		return false;
	}

	/**
	 * Returns a display text for this field matcher, for example, {@code Foo.bar}.
	 * @return the display text
	 */
	public String getDisplayText() {
		if (fieldName != null) {
			return dataType.getName() + '.' + fieldName;
		}
		if (!fieldOffsets.isEmpty()) {
			String compositeFieldName = generateCompositeFieldNameByOffset();
			if (compositeFieldName != null) {
				return compositeFieldName;
			}
			return dataType.getName() + " at " + fieldOffsets.toString();
		}
		return dataType.getName();
	}

	private String generateCompositeFieldNameByOffset() {

		long n = fieldOffsets.getNumValues();
		if (n != 1) {
			return null;
		}

		int offset = fieldOffsets.getMin();
		if (dataType instanceof Structure) {
			Structure structure = (Structure) dataType;
			DataTypeComponent dtc = structure.getComponentContaining(offset);
			if (dtc != null) {
				String name = dtc.getFieldName();
				if (name != null) {
					return name;
				}
				return dtc.getDefaultFieldName();
			}
		}
		else if (dataType instanceof Composite) {
			Composite composite = (Composite) dataType;

			DataTypeComponent[] components = composite.getComponents();
			for (DataTypeComponent dtc : components) {
				int dtcOffset = dtc.getOffset();
				if (dtcOffset == offset) {
					return dtc.getFieldName();
				}
			}
		}

		return null;
	}

	public DataType getDataType() {
		return dataType;
	}

	/**
	 * Returns the field name given to this matcher or will attempt to generate a default field
	 * name using the given data type and offset.
	 * @return the field name or null
	 */
	public String getFieldName() {
		if (fieldName != null) {
			return fieldName;
		}
		return generateCompositeFieldNameByOffset();
	}

	@Override
	public String toString() {
		return getDisplayText();
	}

	@Override
	public int hashCode() {
		return Objects.hash(dataType, fieldName, fieldOffsets);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}

		FieldMatcher other = (FieldMatcher) obj;
		if (!Objects.equals(dataType, other.dataType)) {
			return false;
		}
		if (!Objects.equals(fieldName, other.fieldName)) {
			return false;
		}
		if (!Objects.equals(fieldOffsets, other.fieldOffsets)) {
			return false;
		}
		return true;
	}

}
