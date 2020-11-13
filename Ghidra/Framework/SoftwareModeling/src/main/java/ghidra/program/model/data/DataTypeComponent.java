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
/*
 *
 */
package ghidra.program.model.data;

import ghidra.docking.settings.Settings;
import ghidra.util.exception.DuplicateNameException;

/**
 * DataTypeComponents are holders for the dataTypes that make up composite (Structures
 * and Unions) dataTypes.
 * <p>
 * While most all components must have a fixed length greater than 0, structures support an
 * optional trailing flexible array component whose length is zero and whose offset equals
 * the length of the structure.
 */
public interface DataTypeComponent {

	/** The default prefix for the name of a component. */
	public final static String DEFAULT_FIELD_NAME_PREFIX = "field";

	/**
	 * Returns the dataType in this component.
	 * <p>
	 * NOTE: If this component corresponds to a structure flexible array the returned data type
	 * reflects the base type of the array (e.g., char is returned for a flexible char array).
	 * @return the dataType in this component
	 */
	public DataType getDataType();

	/**
	 * returns the dataType that contains this component.
	 * @return the dataType that contains this component.
	 */
	public DataType getParent();

	/**
	 * Determine if this component corresponds to a unsized flexible array which is
	 * permitted as the trailing component within a structure.
	 * @return true if component is a trailing flexible array component.
	 */
	public boolean isFlexibleArrayComponent();

	/**
	 * Determine if the specified component corresponds to a bit-field.
	 * @return true if bit-field else false
	 */
	public boolean isBitFieldComponent();

	/**
	 * Determine if the specified component corresponds to a zero-length bit-field.
	 * @return true if zer-length bit-field else false
	 */
	public boolean isZeroBitFieldComponent();

	/**
	 * Get the ordinal position within the parent dataType.
	 * <p>
	 * NOTE: The special case of a structure flexible array component returns an ordinal equal
	 * to the parent structure's {@link Structure#getNumComponents()} since it is not included
	 * in the list of normal components (see {@link Structure#getFlexibleArrayComponent()}.
	 * @return ordinal of this component within the parent data type.
	 */
	public int getOrdinal();

	/**
	 * Get the byte offset of where this component begins relative to the start of the parent
	 * data type.  
	 * <p>
	 * NOTE: The special case of a structure flexible array component returns an offset equal
	 * to the length of the parent structure since the flexible array component is not included
	 * in a structure's length.
	 * @return offset of start of component relative to the start of the parent
	 * data type. 
	 */
	public int getOffset();

	/**
	 * Get the byte offset of where this component ends relative to the start of the parent
	 * data type.
	 * <p>
	 * NOTE: The special case of a structure flexible array component returns -1 since its
	 * length is undefined.
	 * @return offset of end of component relative to the start of the parent
	 * data type.
	 */
	public int getEndOffset();

	/**
	 * Get the length of this component.
	 * <p>
	 * NOTE: The special case of a structure flexible array component returns 0 since its
	 * length is undefined.
	 * @return the length of this component or 0 for a structure flexible array.
	 */
	public int getLength();

	/**
	 * Get the comment for this dataTypeComponent.
	 */
	public String getComment();

	/**
	 * Gets the default settings for this data type component.
	 * @return a Settings object that is the set of default values for this dataType component
	 */
	public Settings getDefaultSettings();

	/**
	 * Set default settings for this dataType.
	 * @param settings the new default settings.
	 */
	public void setDefaultSettings(Settings settings);

	/**
	 * Sets the comment for the component.
	 * @param comment this components comment.
	 */
	public void setComment(String comment);

	/**
	 * Get the name of the field name as a component of a Data Type.
	 * @return the name as a component of another Data Type.
	 */
	public String getFieldName();

	/**
	 * Sets the field name. If the field name is empty it will be set to null,
	 * which is the default field name. An exception is thrown if one of the
	 * parent's other components already has the specified field name.
	 *
	 * @param fieldName the new field name for this component.
	 *
	 * @throws DuplicateNameException if another component of the parent has
	 * the specified field name.
	 */
	public void setFieldName(String fieldName) throws DuplicateNameException;

	/**
	 * Returns a default Field name.  Used only if a field name is not set.
	 */
	public String getDefaultFieldName();

	/**
	 * Returns true if the given dataTypeComponent is equivalent to this dataTypeComponent.
	 * A dataTypeComponent is "equivalent" if the other component has a data type
	 * that is equivalent to this component's data type. The dataTypeComponents must
	 * also have the same offset, field name, and comment.  The length is only checked
	 * for components which are dyanmic and whose size must be specified when creating
	 * a component.
	 * @param dtc the dataTypeComponent being tested for equivalence.
	 * @return true if the given dataTypeComponent is equivalent to this dataTypeComponent.
	 */
	public boolean isEquivalent(DataTypeComponent dtc);

}
