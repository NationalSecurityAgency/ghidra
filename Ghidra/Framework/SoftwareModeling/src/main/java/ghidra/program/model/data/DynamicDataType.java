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

import ghidra.docking.settings.SettingsImpl;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.datastruct.SoftCacheMap;

/**
 * Interface for dataTypes that don't get applied, but instead generate dataTypes
 * on the fly based on the data.
 */
public abstract class DynamicDataType extends BuiltIn implements Dynamic {
	private SoftCacheMap<Address, DataTypeComponent[]> map;

	protected DynamicDataType(String name) {
		this(CategoryPath.ROOT, name, null);
	}

	protected DynamicDataType(String name, DataTypeManager dtm) {
		this(CategoryPath.ROOT, name, dtm);
	}

	protected DynamicDataType(CategoryPath path, String name) {
		this(path, name, null);
	}

	protected DynamicDataType(CategoryPath path, String name, DataTypeManager dtm) {
		super(path, name, dtm);
		this.map = new SoftCacheMap<>(100);
		defaultSettings = new SettingsImpl();
	}

	@Override
	public final boolean canSpecifyLength() {
		return false;
	}

	/**
	 * Gets the number of component data types in this data type.
	 * @param buf a membuffer to be used by dataTypes that change depending on
	 * their data context.  A null value is acceptable to indicate that a memory
	 * context is not available.  DataTypes that need a context will return -1
	 * if the context is null.
	 * @return the number of components that make up this data prototype
	 *   - if this is an Array, return the number of elements in the array.
	 *   - if this datatype is a subcomponent of another datatype and it
	 *      won't fit in it's defined space, return -1.
	 */
	public final int getNumComponents(MemBuffer buf) {
		DataTypeComponent[] comps = getComps(buf);
		if (comps != null) {
			return comps.length;
		}
		return -1;
	}

	protected DataTypeComponent[] getComps(MemBuffer buf) {
		Address addr = buf.getAddress();
		DataTypeComponent[] comps = map.get(addr);
		if (comps == null) {
			comps = getAllComponents(buf);
			if (comps == null) {
				// data-type not valid at buf location
				return null;
			}
			map.put(addr, comps);
		}
		return comps;
	}

	/**
	 * Returns the immediate n'th component of this data type.
	 * @param index the components index (zero based).
	 * @param buf a membuffer to be used by dataTypes that change depending on
	 * their data context.  A null value is acceptable to indicate that a memory
	 * context is not available.  DataTypes that need a context will return -1
	 * if the context is null.
	 * @return the component data type or null if there is no component at the 
	 * indicated index.
	 */
	public final DataTypeComponent getComponent(int index, MemBuffer buf) {
		DataTypeComponent[] comps = getComps(buf);
		if (comps != null) {
			return comps[index];
		}
		return null;
	}

	/**
	 * Returns an array of DataTypes that make up this data type.
	 * Could return null if there are no subcomponents.
	 * If this is an Array, then only one element will be returned
	 * which is the Data Prototype for the elements in the array.
	 * Will return null if this is a subcomponent that doesn't fit in it's
	 * alloted space.
	 * @param buf a membuffer to be used by dataTypes that change depending on
	 * their data context.  A null value is acceptable to indicate that a memory
	 * context is not available.  DataTypes that need a context will return -1
	 * if the context is null.
	 */
	public final DataTypeComponent[] getComponents(MemBuffer buf) {
		return getComps(buf);
	}

	/**
	 * Returns the component containing the byte at the given offset
	 * @param offset the offset into the dataType
	 * @param buf the memoryBuffer containing the bytes.
	 * @return the component containing the byte at the given offset
	 */
	public final DataTypeComponent getComponentAt(int offset, MemBuffer buf) {
		DataTypeComponent[] comps = getComps(buf);
		if (comps == null) {
			return null;
		}
		for (int i = 0; i < comps.length; i++) {
			if (comps[i].getOffset() > offset) {
				return comps[i - 1];
			}
		}
		int index = comps.length - 1;
		if (index < 0) {
			return null;
		}
		return comps[index];

	}

	/**
	 * Get all dynamic components associated with the specified MemBuffer
	 * @param buf memory buffer positioned at start of data type instance
	 * @return all components or null if memory data is not valid for this
	 * data type.
	 */
	protected abstract DataTypeComponent[] getAllComponents(MemBuffer buf);

	@Override
	public final int getLength(MemBuffer buf, int maxLength) {
		DataTypeComponent[] comps = getComps(buf);
		if ((comps == null) || (comps.length < 1)) {
			return -1;
		}
		DataTypeComponent last = comps[comps.length - 1];
		if (last == null) {
			return -1;
		}
		return last.getOffset() + last.getLength();
	}

	@Override
	public int getLength() {
		return -1;
	}

	public void invalidateCache() {
		map.clear();
	}

	@Override
	public DataType getReplacementBaseType() {
		return ByteDataType.dataType;
	}
}
