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
import ghidra.util.Msg;
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
	 * @param buf a memory buffer to be used by dataTypes that change depending on
	 * their data context. 
	 * @return the number of components that make up this data prototype
	 *   - if this is an Array, return the number of elements in the array.
	 *   - if this datatype is a subcomponent of another datatype and it
	 *      won't fit in it's defined space, return -1.
	 */
	public final int getNumComponents(MemBuffer buf) {
		DataTypeComponent[] comps = getComps(buf);
		if (comps == null || comps.length == 0) {
			return -1;
		}
		DataTypeComponent last = comps[comps.length - 1];
		return (last != null && last.isFlexibleArrayComponent()) ? (comps.length - 1)
				: comps.length;
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
			for (int i = 0; i < comps.length - 1; i++) {
				// TODO: should we verify ordinals
				if (comps[i] != null && comps[i].isFlexibleArrayComponent()) {
					// Only the last component may be a flexible array
					Msg.error(this,
						getClass().getName() + " produced invalid flexible array component");
					return null;
				}
			}
			map.put(addr, comps);
		}
		return comps;
	}

	/**
	 * Returns the immediate n'th component of this data type.
	 * @param ordinal the components ordinal (zero based).
	 * @param buf a memory buffer to be used by dataTypes that change depending on
	 * their data context.
	 * @return the component data type or null if there is no component at the 
	 * indicated index.
	 * @throws ArrayIndexOutOfBoundsException if index is out of bounds
	 */
	public final DataTypeComponent getComponent(int ordinal, MemBuffer buf) {
		DataTypeComponent[] comps = getComps(buf);
		if (comps != null) {
			DataTypeComponent dtc = comps[ordinal];
			if (dtc != null && !dtc.isFlexibleArrayComponent()) {
				return dtc;
			}
		}
		return null;
	}

	/**
	 * Returns an array of components that make up this data type.
	 * Could return null if there are no subcomponents.  The last component
	 * in the array may be a flexible array component.
	 * @param buf a memory buffer to be used by dataTypes that change depending on
	 * their data context.
	 * @return datatype component array or null.  Last component may be a flexible array component.
	 */
	public final DataTypeComponent[] getComponents(MemBuffer buf) {
		return getComps(buf);
	}

	/**
	 * Returns the first component containing the byte at the given offset
	 * @param offset the offset into the dataType
	 * @param buf the memory buffer containing the bytes.
	 * @return the component containing the byte at the given offset or null if no
	 * component defined.
	 */
	public final DataTypeComponent getComponentAt(int offset, MemBuffer buf) {
		DataTypeComponent[] comps = getComps(buf);
		if (comps == null) {
			return null;
		}
		// TODO: could use binary search (watchout for bitfields at same offset)
		for (DataTypeComponent comp : comps) {
			if (comp == null) {
				continue;
			}
			if (comp.isFlexibleArrayComponent()) {
				return null;
			}
			if (offset >= comp.getOffset() &&
				(offset <= (comp.getOffset() + comp.getLength() - 1))) {
				return comp;
			}
		}
		return null;
	}

	/**
	 * Get all dynamic components associated with the specified MemBuffer
	 * @param buf memory buffer positioned at start of data type instance
	 * @return all components or null if memory data is not valid for this
	 * data type.  Last component may be a flexible array component.
	 */
	protected abstract DataTypeComponent[] getAllComponents(MemBuffer buf);

	@Override
	public final int getLength(MemBuffer buf, int maxLength) {
		DataTypeComponent[] comps = getComps(buf);
		if ((comps == null) || (comps.length < 1)) {
			return -1;
		}
		DataTypeComponent last = comps[comps.length - 1];
		if (last != null && last.isFlexibleArrayComponent()) {
			return last.getOffset();
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

	/**
	 * Get trailing flexible array component.
	 * @return flexible array component or null if not applicable or valie.
	 */
	public final DataTypeComponent getFlexibleArrayComponent(MemBuffer buf) {
		DataTypeComponent[] comps = getComps(buf);
		if (comps == null || comps.length == 0) {
			return null;
		}
		DataTypeComponent last = comps[comps.length - 1];
		if (last != null && last.isFlexibleArrayComponent()) {
			return last;
		}
		return null;
	}
}
