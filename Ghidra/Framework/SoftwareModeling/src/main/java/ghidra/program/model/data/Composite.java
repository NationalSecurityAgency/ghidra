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

import java.util.Set;

/**
 * Interface for common methods in Structure and Union
 */
public interface Composite extends DataType {

	/**
	 * Sets the string describing this data type.
	 * @param desc the new description.
	 */
	@Override
	public void setDescription(String desc);

	/**
	 * Gets the number of component data types in this composite.
	 * If this is Structure with packing disabled, the count will include all undefined filler
	 * components which may be present.  In addition, Structures do not include the
	 * optional trailing flexible array component in this count 
	 * (see {@link Structure#hasFlexibleArrayComponent()}).
	 * @return the number of components that make up this composite
	 */
	public abstract int getNumComponents();

	/**
	 * Returns the number of explicitly defined components in this composite. 
	 * For Unions and packed Structures this is equivalent to {@link #getNumComponents()} 
	 * since they do not contain undefined components.  
	 * This count will always exclude all undefined filler components which may be present 
	 * within a Structure whoose packing is disabled (see {@link #isPackingEnabled()}).
	 * In addition, Structures do not include the
	 * optional trailing flexible array component in this count 
	 * (see {@link Structure#hasFlexibleArrayComponent()}).
	 * @return  the number of explicitly defined components in this composite
	 */
	public abstract int getNumDefinedComponents();

	/**
	 * Returns the component of this data type with the indicated ordinal.
	 * @param ordinal the component's ordinal (zero based).
	 * @return the data type component.
	 * @throws IndexOutOfBoundsException if the ordinal is out of bounds
	 */
	public abstract DataTypeComponent getComponent(int ordinal) throws IndexOutOfBoundsException;

	/**
	 * Returns an array of Data Type Components that make up this composite including
	 * undefined filler components which may be present within a Structure whch has packing disabled.
	 * Structures do not include the optional trailing flexible array component in the returned array.
	 * The number of components corresponds to {@link #getNumComponents()}.
	 * @return array all components
	 */
	public abstract DataTypeComponent[] getComponents();

	/**
	 * Returns an array of Data Type Components that make up this composite excluding
	 * undefined filler components which may be present within Structures where packing is disabled.
	 * The number of components corresponds to {@link #getNumDefinedComponents()}.  For Unions and 
	 * packed Structures this is equivalent to {@link #getComponents()} 
	 * since they do not contain undefined filler components.  Structures do not include the
	 * optional trailing flexible array component in the returned array 
	 * (see {@link Structure#getFlexibleArrayComponent()}).
	 * @return array all explicitly defined components
	 */
	public abstract DataTypeComponent[] getDefinedComponents();

	/**
	 * Adds a new datatype to the end of this composite.  This is the preferred method
	 * to use for adding components to an aligned structure for fixed-length dataTypes.
	 * @param dataType the datatype to add.
	 * @return the DataTypeComponent created.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to be added to this composite data type.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to add dt1 to dt2 since this would cause a cyclic dependency.
	 */
	public DataTypeComponent add(DataType dataType) throws IllegalArgumentException;

	/**
	 * Adds a new datatype to the end of this composite. This is the preferred method
	 * to use for adding components to an aligned structure for dynamic dataTypes such as 
	 * strings whose length must be specified.
	 * @param dataType the datatype to add.
	 * @param length the length to associate with the datatype.
	 * For fixed length types a length &lt;= 0 will use the length of the resolved dataType.
	 * @return the componentDataType created.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to be added to this composite data type or an invalid length
	 * is specified.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to add dt1 to dt2 since this would cause a cyclic dependency.
	 */
	public DataTypeComponent add(DataType dataType, int length) throws IllegalArgumentException;

	/**
	 * Adds a new datatype to the end of this composite.  This is the preferred method
	 * to use for adding components to an aligned structure for fixed-length dataTypes.
	 * @param dataType the datatype to add.
	 * @param name the field name to associate with this component.
	 * @param comment the comment to associate with this component.
	 * @return the componentDataType created.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to be added to this composite data type.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to add dt1 to dt2 since this would cause a cyclic dependency.
	 */
	public DataTypeComponent add(DataType dataType, String name, String comment)
			throws IllegalArgumentException;

	/**
	 * Adds a new bitfield to the end of this composite.  This method is intended 
	 * to be used with packed structures/unions only where the bitfield will be 
	 * appropriately packed.  The minimum storage storage byte size will be applied.
	 * It will not provide useful results for composites with packing disabled.
	 * @param baseDataType the bitfield base datatype (certain restrictions apply).
	 * @param bitSize the bitfield size in bits
	 * @param componentName the field name to associate with this component.
	 * @param comment the comment to associate with this component.
	 * @return the componentDataType created whose associated data type will
	 * be BitFieldDataType.
	 * @throws InvalidDataTypeException if the specified data type is
	 * not a valid base type for bitfields.
	 */
	public DataTypeComponent addBitField(DataType baseDataType, int bitSize, String componentName,
			String comment) throws InvalidDataTypeException;

	/**
	 * Adds a new datatype to the end of this composite.  This is the preferred method
	 * to use for adding components to an aligned structure for dynamic dataTypes such as 
	 * strings whose length must be specified.
	 * @param dataType the datatype to add.
	 * @param length the length to associate with the datatype.
	 * For fixed length types a length &lt;= 0 will use the length of the resolved dataType.
	 * @param name the field name to associate with this component.
	 * @param comment the comment to associate with this component.
	 * @return the componentDataType created.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to be added to this composite data type or an invalid length is specified.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to add dt1 to dt2 since this would cause a cyclic dependency.
	 */
	public DataTypeComponent add(DataType dataType, int length, String name, String comment)
			throws IllegalArgumentException;

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
	 * @throws IndexOutOfBoundsException if component ordinal is out of bounds
	 */
	public DataTypeComponent insert(int ordinal, DataType dataType)
			throws IndexOutOfBoundsException, IllegalArgumentException;

	/**
	 * Inserts a new datatype at the specified ordinal position in this composite.
	 * <BR>Note: For an aligned structure the ordinal position will get adjusted
	 * automatically to provide the proper alignment.
	 * @param ordinal the ordinal where the new datatype is to be inserted.	
	 * @param dataType the datatype to insert.
	 * @param length the length to associate with the datatype.
	 * For fixed length types a length &lt;= 0 will use the length of the resolved dataType.
	 * @return the componentDataType created.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to be inserted into this composite data type or an invalid 
	 * length is specified.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to insert dt1 to dt2 since this would cause a cyclic dependency.
	 * @throws IndexOutOfBoundsException if component ordinal is out of bounds
	 */
	public DataTypeComponent insert(int ordinal, DataType dataType, int length)
			throws IndexOutOfBoundsException, IllegalArgumentException;

	/**
	 * Inserts a new datatype at the specified ordinal position in this composite.
	 * <BR>Note: For an aligned structure the ordinal position will get adjusted
	 * automatically to provide the proper alignment.
	 * @param ordinal the ordinal where the new datatype is to be inserted.	
	 * @param dataType the datatype to insert.
	 * @param length the length to associate with the datatype.
	 * For fixed length types a length &lt;= 0 will use the length of the resolved dataType.
	 * @param name the field name to associate with this component.
	 * @param comment the comment to associate with this component.
	 * @return the componentDataType created.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to be inserted into this composite data type or an invalid length
	 * is specified.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to insert dt1 to dt2 since this would cause a cyclic dependency.
	 * @throws IndexOutOfBoundsException if component ordinal is out of bounds
	 */
	public DataTypeComponent insert(int ordinal, DataType dataType, int length, String name,
			String comment) throws IndexOutOfBoundsException, IllegalArgumentException;

	/**
	 * Deletes the component at the given ordinal position.
	 * <BR>Note: Removal of bitfields from a structure with packing disabled will 
	 * not shift other components causing vacated bytes to revert to undefined filler.
	 * @param ordinal the ordinal of the component to be deleted.
	 * @throws IndexOutOfBoundsException if component ordinal is out of bounds
	 */
	public void delete(int ordinal) throws IndexOutOfBoundsException;

	/**
	 * Deletes the specified set of components at the given ordinal positions.
	 * <BR>Note: Removal of bitfields from a structure with packing disabled will 
	 * not shift other components causing vacated bytes to revert to undefined filler.
	 * @param ordinals the ordinals of the component to be deleted.
	 * @throws IndexOutOfBoundsException if any specified component ordinal is out of bounds
	 */
	public void delete(Set<Integer> ordinals) throws IndexOutOfBoundsException;

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
	 * The alignment changed for the specified data type.  If packing is enabled for this
	 * composite, the placement of the component may be affected by a change in its alignment.
	 * A non-packed composite can ignore this notification.
	 * @param dt the data type whose alignment changed.
	 */
	@Override
	public void dataTypeAlignmentChanged(DataType dt);

	/**
	 * Updates packed composite to any changes in the data organization. If the composite does
	 * not have packing enabled this method does nothing.
	 * <BR>
	 * NOTE: Changes to data organization is discouraged.  Attempts to use this method in such
	 * cases should be performed on all composites in dependency order (ignoring pointer components).
	 */
	public void repack();

	/**
	 * @return the packing type set for this composite
	 */
	public PackingType getPackingType();

	/**
	 * Determine if this data type has its internal components currently packed
	 * based upon alignment and packing settings.  If disabled, component placement
	 * is based upon explicit placement by offset.
	 * @return true if this data type's components auto-packed
	 */
	public default boolean isPackingEnabled() {
		return getPackingType() != PackingType.DISABLED;
	}

	/**
	 * Sets whether this data type's internal components are currently packed.  The 
	 * affect of disabled packing differs between {@link Structure} and {@link Union}.  When
	 * packing disabled:
	 * <ul>
	 * <li>Structures utilize explicit component offsets and produce undefined filler
	 * components where defined components do not consume space.</li>
	 * <li>Unions always place components at offset 0 and do not pad for alignment.
	 * </ul>
	 * In addition, when packing is disabled the default alignment is always 1 unless a
	 * different minimum alignment has been set.  When packing is enabled the overall 
	 * composite length infleunced by the composite's minimum alignment setting.
	 * If a change in enablement occurs, the default alignment and packing behavior 
	 * will be used.
	 * @param enabled true enables packing of components respecting component 
	 * alignment and pack setting, whereas false disables packing.
	 */
	public void setPackingEnabled(boolean enabled);

	/**
	 * Determine if packing is enabled with an explicit packing value (see {@link #getExplicitPackingValue()}).
	 * @return true if packing is enabled with an explicit packing value, else false.
	 */
	public default boolean hasExplicitPackingValue() {
		return getPackingType() == PackingType.EXPLICIT;
	}

	/**
	 * Determine if default packing is enabled.
	 * @return true if default packing is enabled.
	 */
	public default boolean hasDefaultPacking() {
		return getPackingType() == PackingType.DEFAULT;
	}

	/**
	 * Gets the current packing value (typically a power of 2). 
	 * If this isn't a packed composite with an explicit packing value (see {@link #hasExplicitPackingValue()}) 
	 * then the return value is undefined. 
	 * @return the current packing value or an undefined non-positive value
	 */
	public int getExplicitPackingValue();

	/**
	 * Sets the pack value for this composite (positive value, usually a power of 2). 
	 * If packing was previously disabled, packing will be enabled.  This value will 
	 * establish the maximum effective alignment for this composite and each of the 
	 * components during the alignment computation (e.g., a value of 1 will eliminate 
	 * any padding).  The overall composite length may be infleunced by the composite's
	 * minimum alignment setting.
	 * @param packingValue the new positive packing value.
	 * @throws IllegalArgumentException if a non-positive value is specified.
	 */
	public void setExplicitPackingValue(int packingValue);

	/**
	 * Same as {@link #setExplicitPackingValue(int)}.
	 * @param packingValue the new positive packing value.
	 * @throws IllegalArgumentException if a non-positive value is specified.
	 */
	public default void pack(int packingValue) {
		setExplicitPackingValue(packingValue);
	}

	/**
	 * Enables default packing behavior. 
	 * If packing was previously disabled, packing will be enabled.  
	 * Composite will automatically pack based upon the alignment requirements
	 * of its components with overall composite length possibly infleunced by the composite's
	 * minimum alignment setting.
	 */
	public void setToDefaultPacking();

	/**
	 * Get the computed alignment for this composite based upon packing and minimum
	 * alignment settings as well as component alignment.  If packing is disabled,
	 * the alignment will always be 1 unless a minimum alignment has been set.
	 * @return this composites alignment
	 */
	@Override
	abstract int getAlignment();

	/**
	 * @return the alignment type set for this composite
	 */
	abstract AlignmentType getAlignmentType();

	/**
	 * Whether or not this data type is using the default alignment.  When Structure packing 
	 * is disabled the default alignment is always 1 (see {@link Structure#setPackingEnabled(boolean)}.
	 * @return true if this data type is using its default alignment. 
	 */
	public default boolean isDefaultAligned() {
		return getAlignmentType() == AlignmentType.DEFAULT;
	}

	/**
	 * Whether or not this data type is using the machine alignment value, specified by 
	 * {@link DataOrganization#getMachineAlignment()}, for its alignment.
	 * @return true if this data type is using the machine alignment as its alignment.
	 */
	public default boolean isMachineAligned() {
		return getAlignmentType() == AlignmentType.MACHINE;
	}

	/**
	 * Determine if an explicit minimum alignment has been set (see {@link #getExplicitMinimumAlignment()}).
	 * An undefined value is returned if default alignment or machine alignment is enabled.
	 * @return true if an explicit minimum alignment has been set, else false
	 */
	public default boolean hasExplicitMinimumAlignment() {
		return getAlignmentType() == AlignmentType.EXPLICIT;
	}

	/**
	 * Get the explicitminimum alignment setting for this Composite which contributes 
	 * to the actual computed alignment value (see {@link #getAlignment()}.
	 * @return the minimum alignment setting for this Composite or an undefined 
	 * non-positive value if an explicit minimum alignment has not been set.
	 */
	public int getExplicitMinimumAlignment();

	/**
	 * Sets this data type's explicit minimum alignment (positive value).  
	 * Together with the pack setting and component alignments will
	 * affect the actual computed alignment of this composite.
	 * When packing is enabled, the alignment setting may also affect padding 
	 * at the end of the composite and its length.  When packing is disabled,
	 * this setting will not affect the length of thhis composite. 
	 * @param minAlignment the minimum alignment for this Composite.
	 * @throws IllegalArgumentException if a non-positive value is specified
	 */
	public void setExplicitMinimumAlignment(int minAlignment);

	/**
	 * Same as {@link #setExplicitMinimumAlignment(int)}.
	 * @param minAlignment the explicit minimum alignment for this Composite.
	 * @throws IllegalArgumentException if a non-positive value is specified
	 */
	public default void align(int minAlignment) {
		setExplicitMinimumAlignment(minAlignment);
	}

	/**
	 * Sets this data type's alignment to its default alignment. For packed
	 * composites, this data type's alignment will be based upon the components it contains and
	 * its current pack settings.  This is the default state and only needs to be used 
	 * when changing from a non-default alignment type. 
	 */
	public void setToDefaultAligned();

	/**
	 * Sets this data type's minimum alignment to the machine alignment which is 
	 * specified by {@link DataOrganization#getMachineAlignment()}. The machine alignment is 
	 * defined as the maximum useful alignment for the target machine.
	 */
	public void setToMachineAligned();

}
