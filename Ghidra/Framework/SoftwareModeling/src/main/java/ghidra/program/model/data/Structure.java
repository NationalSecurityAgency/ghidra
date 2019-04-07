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

import ghidra.util.exception.InvalidInputException;

/**
 * The structure interface.
 * 
 * NOTE: Structures containing only a flexible array will report a length of 1
 * which will result in improper code unit sizing since we are unable to support a 
 * defined data of length 0.
 */
public interface Structure extends Composite {

	/**
	 * Returns the component of this structure with the indicated ordinal.
	 * If the specified ordinal equals {@link #getNumComponents()} the defined 
	 * flexible array component will be returned, otherwise an out of bounds
	 * exception will be thrown. Use of {@link #getFlexibleArrayComponent()} is preferred 
	 * for obtaining this special trailing component.
	 * @param ordinal the component's ordinal (zero based).
	 * @return the data type component.
	 * @throws ArrayIndexOutOfBoundsException if the ordinal is out of bounds
	 */
	@Override
	public abstract DataTypeComponent getComponent(int ordinal);

	/**
	 * Gets the immediate child component that contains the byte
	 * at the given offset.
	 * @param offset the byte offset into this data type
	 * @return the immediate child component.
	 */
	public abstract DataTypeComponent getComponentAt(int offset);

	/**
	 * Returns the primitive Data Type that is at this offset.  This is useful
	 * for prototypes that have components that are made up of other components
	 * @param offset the byte offset into this data type.
	 * @return the primitive data type at the offset.
	 */
	public abstract DataTypeComponent getDataTypeAt(int offset);

	/**
	 * 
	 * @see ghidra.program.model.data.Composite#add(ghidra.program.model.data.DataType)
	 */
	@Override
	public DataTypeComponent add(DataType dataType);

	/**
	 * 
	 * @see ghidra.program.model.data.Composite#add(ghidra.program.model.data.DataType, int)
	 */
	@Override
	public DataTypeComponent add(DataType dataType, int length);

	/**
	 * 
	 * @see ghidra.program.model.data.Composite#add(ghidra.program.model.data.DataType, int, java.lang.String, java.lang.String)
	 */
	@Override
	public DataTypeComponent add(DataType dataType, int length, String name, String comment);

	/**
	 * 
	 * @see ghidra.program.model.data.Composite#insert(int, ghidra.program.model.data.DataType)
	 */
	@Override
	public DataTypeComponent insert(int index, DataType dataType);

	/**
	 * 
	 * @see ghidra.program.model.data.Composite#insert(int, ghidra.program.model.data.DataType, int)
	 */
	@Override
	public DataTypeComponent insert(int index, DataType dataType, int length);

	/**
	 * 
	 * @see ghidra.program.model.data.Composite#insert(int, ghidra.program.model.data.DataType, int, java.lang.String, java.lang.String)
	 */
	@Override
	public DataTypeComponent insert(int index, DataType dataType, int length, String name,
			String comment);

	public void insert(int ordinal, DataType dataType, int length, String name, String comment,
			int numCopies);

	/**
	 * Deletes the ComponentDataType at the given index
	 * @param index the index of the component to be deleted.
	 */
	@Override
	public void delete(int index);

	/**
	 * Inserts a new datatype at the specified offset into this structure.
	 * @param offset the byte offset into the structure where the new datatype is to be inserted.	
	 * @param dataType the datatype to insert.
	 * @return the componentDataType created.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to be inserted into this composite data type.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to insert dt1 to dt2 since this would cause a cyclic dependency.
	 */
	public DataTypeComponent insertAtOffset(int offset, DataType dataType, int length);

	/**
	 * Inserts a new datatype at the specified offset into this structure.
	 * @param offset the byte offset into the structure where the new datatype is to be inserted.	
	 * @param dataType the datatype to insert.
	 * @param length the length to associate with the dataType;
	 * @param name the field name to associate with this component.
	 * @param comment the comment to associate with this component.
	 * @return the componentDataType created.
	 * @throws IllegalArgumentException if the dataType.getLength() is positive 
	 * and does not match the given length parameter.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to be inserted into this composite data type.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to insert dt1 to dt2 since this would cause a cyclic dependency.
	 */
	public DataTypeComponent insertAtOffset(int offset, DataType dataType, int length, String name,
			String comment);

	/**
	 * Deletes the datatype at the specified offset in this structure.
	 * @param offset the byte offset into the structure where the datatype is to be deleted.	
	 */
	public void deleteAtOffset(int offset);

	/**
	 * Remove all components from this structure, effectively setting the
	 * length to zero.
	 *
	 */
	public void deleteAll();

	/**
	 * clears the defined component at the given component index.  Clearing a 
	 * component causes a defined component to be replaced with a number of
	 * undefined dataTypes to offset the removal of the defined dataType.
	 * @param index the index of the component to clear.
	 */
	public void clearComponent(int index);

	/**
	 * Replaces the component at the given component index with a new component
	 * of the indicated data type.
	 * @param index the index where the datatype is to be replaced.	
	 * @param dataType the datatype to insert.
	 * @param length the length of the dataType to insert
	 * @return the new componentDataType at the index.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to replace a component in this composite data type.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to replace a dt2 component with dt1 since this would cause a cyclic 
	 * dependency.
	 */
	public DataTypeComponent replace(int index, DataType dataType, int length);

	/**
	 * Replaces the component at the given component index with a new component
	 * of the indicated data type.
	 * @param index the index where the datatype is to be replaced.	
	 * @param dataType the datatype to insert.
	 * @param length the length to associate with the dataType;
	 * @param name the field name to associate with this component.
	 * @param comment the comment to associate with this component.
	 * @return the new componentDataType at the index.
	 * @throws IllegalArgumentException if the dataType.getLength() is positive 
	 * and does not match the given length parameter.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to replace a component in this composite data type.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to replace a dt2 component with dt1 since this would cause a cyclic 
	 * dependency.
	 */
	public DataTypeComponent replace(int index, DataType dataType, int length, String name,
			String comment);

	/**
	 * Replaces the component at the specified byte offset with a new component
	 * of the indicated data type.
	 * @param offset the byte offset into the structure where the datatype is 
	 * to be replaced.	
	 * @param dataType the datatype to insert.
	 * @param length the length to associate with the dataType;
	 * @param name the field name to associate with this component.
	 * @param comment the comment to associate with this component.
	 * @return the new componentDataType at the index.
	 * @throws IllegalArgumentException if the dataType.getLength() is positive 
	 * and does not match the given length parameter.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to replace a component in this composite data type.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to replace a dt2 component with dt1 since this would cause a cyclic 
	 * dependency.
	 */
	public DataTypeComponent replaceAtOffset(int offset, DataType dataType, int length, String name,
			String comment);

	/**
	 * Returns a list of all components that make up this data type excluding any trailing
	 * flexible array component if present.
	 * @return an array containing the components
	 */
	@Override
	public abstract DataTypeComponent[] getComponents();

	/**
	 * Returns the list of components that are defined. (As opposed to "filler"
	 * undefined bytes.).  Any trailing flexible array component will be omitted.
	 */
	public DataTypeComponent[] getDefinedComponents();

	/**
	 * Determine if a trailing flexible array component has been defined.
	 * @return true if trailing flexible array component has been defined.
	 */
	public boolean hasFlexibleArrayComponent();

	/**
	 * Get the optional trailing flexible array component associated with this structure.
	 * @return optional trailing flexible array component associated with this structure or null
	 * if not present.
	 */
	public DataTypeComponent getFlexibleArrayComponent();

	/**
	 * Set the optional trailing flexible array component associated with this structure.
	 * @param flexType the flexible array dataType (example: for 'char[0]' the type 'char' should be specified)
	 * @param name component field name or null for default name
	 * @param comment component comment
	 * @return updated flexible array component
	 */
	public DataTypeComponent setFlexibleArrayComponent(DataType flexType, String name,
			String comment);

	/**
	 * Remove the optional trailing flexible array component associated with this structure.
	 */
	public void clearFlexibleArrayComponent();

	/**
	 * Gets the number of component data types in this data type excluding any trailing flexible
	 * array component if present. 
	 * @return the number of components that make up this data prototype
	 */
	@Override
	public abstract int getNumComponents();

	/**
	 * Returns the number of non-undefined components in this composite. For example, say
	 * a structure has an int (4 bytes) at offset 0 and another int at offset 8.  This structure
	 * would have 6 total components (one for each undefined between the two ints), but only
	 * 2 defined components. Any trailing flexible array component will not be included in this count.
	 * @return  the number of non-undefined components in this composite
	 */
	public abstract int getNumDefinedComponents();

	/**
	 * Increases the size of the structure by the given amount by adding undefined datatypes
	 * at the end of the structure.
	 * @param amount the amount by which to grow the structure.
	 * @throws IllegalArgumentException if amount < 1
	 */
	public void growStructure(int amount);

	public void pack(int maxAlignment) throws InvalidInputException;

}
