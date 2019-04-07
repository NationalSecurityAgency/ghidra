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
 * Interface for common methods in Structure and Union
 */
public interface Composite extends DataType {

	/**
	 * AlignmentType defined the three states for the type of alignment of a composite data type.
	 * This can be default aligned, machine aligned or aligned by value.
	 * <BR>This controls how this data type will be aligned within other data types.
	 * <BR><B>Default Aligned</B> means to determine this data type's alignment based upon the
	 * alignments of its components. This is controlled by the Data Organization that is provided
	 * by its data type manager. If there is no data type manager then a default data organization 
	 * is used.
	 * <BR><B>Machine Aligned</B> means this data type's alignment will use a minimum alignment that
	 * is the machine alignment specified by the data organization.
	 * <BR><B>Align By Value</B> means that a "minimum alignment value", which is a power of 2 and 
	 * specified elsewhere, will affect the alignment so that it will be at least the 
	 * indicated value and will be a multiple of the minimum value and of the default value.
	 * <BR>Note: If the data organization specifies a maximum alignment, other than 0, then the
	 * alignment value will not be allowed to exceed the maximum alignment for any of these types.
	 */
	public static enum AlignmentType implements NamedAlignment {
		DEFAULT_ALIGNED("Default Aligned"),
		MACHINE_ALIGNED("Machine Aligned"),
		ALIGNED_BY_VALUE("Align By Value");

		private String name;

		AlignmentType(String name) {
			this.name = name;
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public String toString() {
			return name;
		}
	}

	interface NamedAlignment {
		public String getName();
	}

	public final static int DEFAULT_ALIGNMENT_VALUE = 0;
	public final static int NOT_PACKING = 0;

	/**
	 * Sets the string describing this data type.
	 * @param desc the new description.
	 */
	@Override
	public void setDescription(String desc);

	/**
	 * Gets the number of component data types in this data type.
	 * @return the number of components that make up this data prototype
	 */
	public abstract int getNumComponents();

	/**
	 * Returns the component of this data type with the indicated ordinal.
	 * @param ordinal the component's ordinal (zero based).
	 * @return the data type component.
	 * @throws ArrayIndexOutOfBoundsException if the ordinal is out of bounds
	 */
	public abstract DataTypeComponent getComponent(int ordinal);

	/**
	 * Returns an array of Data Type Components that make up this data type.
	 * Returns an array of length 0 if there are no subcomponents.
	 */
	public abstract DataTypeComponent[] getComponents();

	/**
	 * Adds a new datatype to the end of this composite.
	 * @param dataType the datatype to add.
	 * @return the DataTypeComponent created.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to be added to this composite data type.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to add dt1 to dt2 since this would cause a cyclic dependency.
	 */
	public DataTypeComponent add(DataType dataType);

	/**
	 * Adds a new datatype to the end of this composite.
	 * @param dataType the datatype to add.
	 * @param length the length to associate with the datatype.
	 * @return the componentDataType created.
	 * @throws IllegalArgumentException if the dataType.getLength() is positive 
	 * and does not match the given length parameter.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to be added to this composite data type.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to add dt1 to dt2 since this would cause a cyclic dependency.
	 */
	public DataTypeComponent add(DataType dataType, int length);

	/**
	 * Adds a new datatype to the end of this composite.
	 * @param dataType the datatype to add.
	 * @param name the field name to associate with this component.
	 * @param comment the comment to associate with this component.
	 * @return the componentDataType created.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to be added to this composite data type.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to add dt1 to dt2 since this would cause a cyclic dependency.
	 */
	public DataTypeComponent add(DataType dataType, String name, String comment);

	/**
	 * Adds a new datatype to the end of this composite.
	 * @param dataType the datatype to add.
	 * @param length the length to associate with the datatype.
	 * @param name the field name to associate with this component.
	 * @param comment the comment to associate with this component.
	 * @return the componentDataType created.
	 * @throws IllegalArgumentException if the dataType.getLength() is positive 
	 * and does not match the given length parameter.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to be added to this composite data type.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to add dt1 to dt2 since this would cause a cyclic dependency.
	 */
	public DataTypeComponent add(DataType dataType, int length, String name, String comment);

	/**
	 * Inserts a new datatype at the specified ordinal position in this composite.
	 * <BR>Note: For an aligned structure the ordinal position will get adjusted
	 * automatically to provide the proper alignment.
	 * @param ordinal the ordinal where the new datatype is to be inserted.	
	 * @param dataType the datatype to insert.
	 * @return the componentDataType created.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to be inserted into this composite data type.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to insert dt1 to dt2 since this would cause a cyclic dependency.
	 */
	public DataTypeComponent insert(int ordinal, DataType dataType);

	/**
	 * Inserts a new datatype at the specified ordinal position in this composite.
	 * <BR>Note: For an aligned structure the ordinal position will get adjusted
	 * automatically to provide the proper alignment.
	 * @param ordinal the ordinal where the new datatype is to be inserted.	
	 * @param dataType the datatype to insert.
	 * @param length the length to associate with the datatype.
	 * @return the componentDataType created.
	 * @throws IllegalArgumentException if the dataType.getLength() is positive 
	 * and does not match the given length parameter.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to be inserted into this composite data type.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to insert dt1 to dt2 since this would cause a cyclic dependency.
	 */
	public DataTypeComponent insert(int ordinal, DataType dataType, int length);

	/**
	 * Inserts a new datatype at the specified ordinal position in this composite.
	 * <BR>Note: For an aligned structure the ordinal position will get adjusted
	 * automatically to provide the proper alignment.
	 * @param ordinal the ordinal where the new datatype is to be inserted.	
	 * @param dataType the datatype to insert.
	 * @param length the length to associate with the datatype.
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
	public DataTypeComponent insert(int ordinal, DataType dataType, int length, String name,
			String comment);

	/**
	 * Deletes the component at the given ordinal position.
	 * <BR>Note: For an aligned structure the delete will have no effect if the
	 * ordinal position is a component that provides alignment padding.
	 * @param ordinal the ordinal of the component to be deleted.
	 */
	public void delete(int ordinal);

	/**
	 * Deletes the components at the given ordinal positions.
	 * <BR>Note: For an aligned structure the delete will have no effect if the
	 * ordinal position is a component that provides alignment padding.
	 * @param ordinals the ordinals of the component to be deleted.
	 */
	public void delete(int[] ordinals);

	/**
	 * Check if a data type is part of this data type.  A data type could
	 * be part of another by:
	 * <br>Being the same data type.
	 * <br>containing the data type directly
	 * <br>containing another data type that has the data type as a part of it.
	 * @param dataType the data type to look for.
	 * @return true if the indicated data type is part of a sub-component of 
	 * this data type.
	 */
	public abstract boolean isPartOf(DataType dataType);

	/**
	 * Updates the composite to any changes in the data organization. If the composite is not
	 * internally aligned, this method does nothing.
	 */
	public void realign();

	/**
	 * Determine if this data type has its internal components currently aligned.
	 * @return true if this data type's components are aligned relative to each other using the
	 * current data organization. When internally aligned the end of this data type will be padded 
	 * to a multiple of its actual alignment.
	 */
	public boolean isInternallyAligned();

	/**
	 * Sets whether this data type's internal components are currently aligned or unaligned.
	 * @param aligned true means align the internal components of this data type. 
	 * false means don't align it. True also causes the end of this data type to be padded 
	 * to a multiple of its actual alignment.
	 */
	public void setInternallyAligned(boolean aligned);

	/**
	 * The overall (external) alignment changed for the specified data type. 
	 * In other words, the data type has a different alignment when placed inside other structures.
	 * @param dt the data type whose alignment changed.
	 */
	public void dataTypeAlignmentChanged(DataType dt);

	/**
	 * Gets the current packing value (typically a power of 2). If this isn't a packed data
	 * type then NOT_PACKING is returned. The packing value only pertains to internally aligned composite
	 * data types. Aligned structures allow packing.
	 * @return the current packing value or NOT_PACKING.
	 */
	public int getPackingValue();

	/**
	 * Sets the current packing value (usually a power of 2). A value of NOT_PACKING should be passed 
	 * if this isn't a packed data type. Otherwise this value indicates a maximum alignment
	 * for any component within this data type. Calling this method will cause the data type to
	 * become an internally aligned data type.
	 * <br>Note: If a component's data type has a specific external alignment, it will 
	 * override this value if necessary.
	 * @param packingValue the new packing value or 0NOT_PACKING.
	 * @throws InvalidInputException if the packingValue isn't valid.
	 */
	public void setPackingValue(int packingValue) throws InvalidInputException;

	/**
	 * Get the external alignment (a minimum alignment) for this DataType.
	 * This controls where this data type will get aligned within other data types.
	 * It also causes the end of this data type to get padded so its length is a multiple 
	 * of the alignment.
	 * @return the external alignment for this DataType or DEFAULT_ALIGNMENT_VALUE.
	 */
	public int getMinimumAlignment();

	/**
	 * Sets the external alignment (a minimum alignment) for this DataType.
	 * This controls where this data type will get aligned within other data types.
	 * It also causes the end of this data type to get padded so its length is a multiple 
	 * of the alignment. Calling this method will cause the data type to
	 * become an internally aligned data type.
	 * @param minimumAlignment the external (minimum) alignment for this DataType.
	 * @throws InvalidInputException if the external alignment isn't valid.
	 */
	public void setMinimumAlignment(int minimumAlignment) throws InvalidInputException;

	/**
	 * Sets this data type's external (minimum) alignment to the default alignment. This data type's
	 * external alignment will be based upon the components it contains. This should be used
	 * when a data type doesn't have an alignment attribute specified. Calling this method will 
	 * cause the data type to become an internally aligned data type.
	 */
	public void setToDefaultAlignment();

	/**
	 * Sets this data type's external (minimum) alignment to a multiple of the machine alignment that is 
	 * specified in the DataOrganization. The machine alignment is defined as the maximum useful 
	 * alignment for the target machine. This should be used when a data type has an alignment 
	 * attribute specified without a size (indicating to use the machine alignment).
	 * Calling this method will cause the data type to become an internally aligned data type.
	 */
	public void setToMachineAlignment();

	/**
	 * Whether or not this data type is using the default external (minimum) alignment.
	 * @return true if this data type has the default external alignment.
	 */
	public boolean isDefaultAligned();

	/**
	 * Whether or not this data type is using the machine alignment value from the 
	 * DataOrganization for its external (minimum) alignment.
	 * @return true if this data type is using the machine alignment as the minimum alignment.
	 */
	public boolean isMachineAligned();

}
