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
import ghidra.util.exception.DuplicateNameException;

/**
 * DataTypeComponents are holders for the dataTypes that make up composite (Structures
 * and Unions) dataTypes.
 */
public interface DataTypeComponent {

	// TODO: known issue accessing big-endian data when component-length differs from 
	// datatype length.

	/** The default prefix for the name of a component. */
	public final static String DEFAULT_FIELD_NAME_PREFIX = "field";

	/**
	 * Returns the dataType in this component.
	 * @return the dataType in this component
	 */
	public DataType getDataType();

	/**
	 * returns the dataType that contains this component.
	 * @return the dataType that contains this component.
	 */
	public DataType getParent();

	/**
	 * Determine if the specified component corresponds to a bit-field.
	 * @return true if bit-field else false
	 */
	public boolean isBitFieldComponent();

	/**
	 * Determine if the specified component corresponds to a zero-length bit-field.
	 * @return true if zero-length bit-field else false
	 */
	public boolean isZeroBitFieldComponent();

	/**
	 * Get the ordinal position within the parent dataType.
	 * @return ordinal of this component within the parent data type.
	 */
	public int getOrdinal();

	/**
	 * Get the byte offset of where this component begins relative to the start of the parent
	 * data type.
	 * @return offset of start of component relative to the start of the parent
	 * data type.
	 */
	public int getOffset();

	/**
	 * Get the byte offset of where this component ends relative to the start of the parent
	 * data type.
	 * @return offset of end of component relative to the start of the parent
	 * data type.
	 */
	public int getEndOffset();

	/**
	 * Get the length of this component in 8-bit bytes.  Zero-length components will report a length
	 * of 0 and may overlap other components at the same offset.  Similarly, multiple adjacent
	 * bit-field components may appear to overlap at the byte-level.
	 * @return the length of this component in 8-bit bytes
	 */
	public int getLength();

	/**
	 * Get the comment for this dataTypeComponent.
	 * @return component comment string or null if one has not been set
	 */
	public String getComment();

	/**
	 * Gets the default settings for this data type component.
	 * @return a Settings object that is the set of default values for this dataType component
	 */
	public Settings getDefaultSettings();

	/**
	 * Sets the comment for the component.
	 * @param comment this components comment or null to clear comment.
	 */
	public void setComment(String comment);

	/**
	 * Get this component's field name within its parent.
	 * If this method returns null {@link #getDefaultFieldName()} can be used to obtain a default
	 * generated field name.
	 * @return this component's field name within its parent or null if one has not been set.
	 */
	public String getFieldName();

	/**
	 * Sets the field name. If the field name is empty it will be set to null,
	 * which is the default field name. An exception is thrown if one of the
	 * parent's other components already has the specified field name.
	 *
	 * @param fieldName the new field name for this component.
	 *
	 * @throws DuplicateNameException This is actually never thrown anymore. All the other ways
	 * of naming fields did not perform this check and it would cause quite a bit of churn to 
	 * add that exception to all the other methods that affect field names. So to be consistent,
	 * we no longer do the check in this method.
	 */
	public void setFieldName(String fieldName) throws DuplicateNameException;

	/**
	 * Returns a default field name for this component.  Used only if a field name is not set.
	 * @return default field name (may be null for nameless fields such as a zero-length bitfield).
	 */
	public default String getDefaultFieldName() {
		if (isZeroBitFieldComponent()) {
			return null;
		}
		String name = DEFAULT_FIELD_NAME_PREFIX + getOrdinal();
		if (getParent() instanceof Structure) {
			name += "_0x" + Integer.toHexString(getOffset());
		}
		return name;
	}

	/**
	 * Returns true if the given dataTypeComponent is equivalent to this dataTypeComponent.
	 * A dataTypeComponent is "equivalent" if the other component has a data type
	 * that is equivalent to this component's data type. The dataTypeComponents must
	 * also have the same offset, field name, and comment.  The length is only checked
	 * for components which are dynamic and whose size must be specified when creating
	 * a component.
	 * @param dtc the dataTypeComponent being tested for equivalence.
	 * @return true if the given dataTypeComponent is equivalent to this dataTypeComponent.
	 */
	public boolean isEquivalent(DataTypeComponent dtc);

	/**
	 * Determine if the specified dataType will be treated as a zero-length component
	 * allowing it to possibly overlap the next component.  If the specified dataType
	 * returns true for {@link DataType#isZeroLength()} and true for {@link DataType#isNotYetDefined()}
	 * this method will return false causing the associated component to use the reported dataType length
	 * of 1.
	 * @param dataType datatype to be evaluated
	 * @return true if zero-length component
	 */
	public static boolean usesZeroLengthComponent(DataType dataType) {
		if (dataType.isZeroLength()) {
			if (dataType instanceof TypeDef) {
				// need to check base type since TypeDef always returns false for isNotYetDefined()
				dataType = ((TypeDef) dataType).getBaseDataType();
			}
			if (dataType instanceof Array) {
				return true;
			}
			// assumes undefined types will ultimately have a non-zero length
			return !dataType.isNotYetDefined();
		}
		return false;
	}

	/**
	 * Returns true if this this component is not defined. It is just a placeholder.
	 * @return true if this this component is not defined. It is just a placeholder.
	 */
	public boolean isUndefined();

}
