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
package ghidra.program.model.listing;

import java.util.List;

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeDisplayOptions;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

/**
 * Interface for interacting with data at an address in a program.
 */
public interface Data extends CodeUnit, Settings {

	/**
	 * Returns the value of the data item.  The value may be an address, a scalar,
	 * register or null if no value.
	 * @return the value
	 */
	public Object getValue();

	/**
	 * Get the class used to express the value of this data.
	 * 
	 * <p>NOTE: This determination is made based upon data type and settings only and does not
	 * examine memory bytes which are used to construct the data value object.
	 * 
	 * @return value class or null if a consistent class is not utilized.
	 */
	public Class<?> getValueClass();

	/**
	 * Returns true if this data corresponds to string data.  This is determined
	 * by the corresponding data type producing a String value.
	 * @return true if this data returns a String value and can be treated as string data.
	 */
	public boolean hasStringValue();

	/**
	 * @return true if data is constant.
	 * If true, isConstant will always be false
	 */
	public boolean isConstant();

	/**
	 * @return true if data is volatile.
	 * If true, isVolatile will always be false
	 */
	public boolean isVolatile();

	/**
	 * Returns true if the data type is defined.  Any address that has not been defined to be code
	 * or data is treated as undefined data.
	 * @return true if is defined
	 */
	public boolean isDefined();

	/**
	 * Get the Data type for the data.
	 * @return the data type
	 */
	public DataType getDataType();

	/**
	 * If the dataType is a typeDef, then the typeDef's base type is returned, otherwise, the
	 * datatType is returned.
	 * @return the data type
	 */
	public DataType getBaseDataType();

	/**
	 * Get the references for the value.
	 * @return the references
	 */
	public Reference[] getValueReferences();

	/**
	 * Add a memory reference to the value.
	 * @param refAddr address referenced.
	 * @param type the type of reference to be added.
	 */
	public void addValueReference(Address refAddr, RefType type);

	/**
	 * Remove a reference to the value.
	 * @param refAddr address of reference to be removed.
	 */
	public void removeValueReference(Address refAddr);

	/**
	 * Get the field name of this data item if it is "inside" another data item, otherwise return
	 * null.
	 * @return the name of this data as known from some parent data item or
	 *         null if this data item is not a component of another data item.
	 */
	public String getFieldName();

	/**
	 * Returns the full path name (dot notation) for this field.  This includes the symbol name at
	 * this address.
	 * @return the path name
	 */
	public String getPathName();

	/**
	 * Returns the component path name (dot notation) for this field
	 * @return the component path name
	 */
	public String getComponentPathName();

	/**
	 * Returns true if this is a pointer, implies getValue() will will return an Object that is an
	 * Address.
	 * @return true if a pointer
	 */
	public boolean isPointer();

	/**
	 * Returns true if this data item is a Union.
	 * @return true if a union
	 */
	public boolean isUnion();

	/**
	 * Returns true if this data item is a Structure.
	 * @return true if a structure
	 */
	public boolean isStructure();

	/**
	 * Returns true if this data item is an Array of DataTypes
	 * @return true if an array
	 */
	public boolean isArray();

	/**
	 * Returns true if this data item is a dynamic DataType.
	 * @return true if is dynamic
	 */
	public boolean isDynamic();

	/**
	 * Get the immediate parent data item of this data item or null if this data item is not
	 * contained in another data item.
	 * @return the data
	 */
	public Data getParent();

	/**
	 * Get the highest level Data item in a hierarchy of structures containing this component.
	 * @return the data
	 */
	public Data getRoot();

	/**
	 * Get the offset of this Data item from the start of the root data item of some hierarchy of
	 * structures.
	 * @return the offset
	 */
	public int getRootOffset();

	/**
	 * Get the offset of this Data item from the start of its immediate parent.
	 * @return the offset
	 */
	public int getParentOffset();

	/**
	 * Returns the immediate n'th component or null if none exists.
	 * @param index the index of the component to get.
	 * @return the component
	 */
	public Data getComponent(int index);

	/**
	 * Get a data item given  the index path. Each integer in the array represents an index into
	 * the data item at that level.
	 * @param componentPath the array of indexes to use to find the requested data item.
	 * @return the component
	 */
	public Data getComponent(int[] componentPath);

	/**
	 * Get the component path if this is a component. The component path is an array of integers
	 * that represent each index in the tree of data items. Top level data items have an empty
	 * array for their component path.
	 * @return the path
	 */
	public int[] getComponentPath();

	/**
	 * Return the number of components that make up this data item.
	 * if this is an Array, return the number of elements in the array.
	 * @return the number of components
	 */
	public int getNumComponents();

	/**
	 * Return the first immediate child component that contains the byte at the given offset.  It
	 * is important to note that with certain datatypes there may be more than one component
	 * containing the specified offset (see {@link #getComponentsContaining(int)}).
	 * 
	 * @param offset the amount to add to this data items address to get the address of the
	 * requested data item.
	 * @return first data component containing offset or null
	 * @deprecated method name has been changed to better reflect behavior.  The method
	 * {@link #getComponentContaining(int)} should be used instead.
	 */
	@Deprecated(forRemoval = true, since = "10.1")
	public Data getComponentAt(int offset);

	/**
	 * RReturn the first immediate child component that contains the byte at the given offset.  It
	 * is important to note that with certain datatypes there may be more than one component
	 * containing the specified offset (see {@link #getComponentsContaining(int)}).
	 * 
	 * @param offset the amount to add to this data items address to get the
	 * @return first data component containing offset or null address of the requested data item.
	 */
	public Data getComponentContaining(int offset);

	/**
	 * Returns a list of all the immediate child components that contain the byte at the
	 * given offset.
	 * <P>
	 * For a union, this will return all the components (if the offset is 0).  The presence of bit-fields
	 * or zero-length components may cause multiple components to be returned.
	 * @param offset the amount to add to this data items address to get the
	 * address of the requested data item.
	 * @return a list of all the immediate child components that contain the byte at the
	 * given offset or null if offset is out of bounds.
	 */
	public List<Data> getComponentsContaining(int offset);

	/**
	 * Returns the primitive component containing this offset (i.e., one that does not
	 * have sub-components).  This is useful for data items which are made up of multiple
	 * layers of other data items. This method immediately goes to the lowest level data item.
	 * If the minimum offset of a component is specified, the only first component containing
	 * the offset will be considered (e.g., 0-element array).
	 * @param offset the offset
	 * @return primitive component containing this offset
	 */
	public Data getPrimitiveAt(int offset);

	/**
	 * Get the index of this component in its parent
	 * @return -1 if this data item is not a component of another data item.
	 */
	public int getComponentIndex();

	/**
	 * Get this data's component level in its hierarchy of components.
	 * @return the level of this data item with 0 being the level of top data items.
	 */
	public int getComponentLevel();

	/**
	 * Returns a string that represents the data value without markup.
	 * @return the string
	 */
	public String getDefaultValueRepresentation();

	/**
	 * Returns the appropriate string to use as the default label prefix or null if it has no
	 * preferred default label prefix;
	 * @param options the options
	 * @return the prefix
	 */
	public String getDefaultLabelPrefix(DataTypeDisplayOptions options);
}
