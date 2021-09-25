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
package ghidra.app.util;

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

/**
 * <code>DataComponent</code> provides Data and CodeUnit access to Struct and Array components.
 *
 * NOTE!! DataComponents only have a unique key within its parent Struct/Array.  This places a constraint on
 * the use of the key field and getKey() method on the underlying classes CodeUnitDB and DataDB.
 * The CodeUnit key should only be used for managing an object cache.
 */
class PseudoDataComponent extends PseudoData {

	PseudoData parent;
	DataTypeComponent component;
	private int indexInParent;
	private int offset;
	private int[] path;
	private Settings defaultSettings;

	/**
	 * @throws AddressOverflowException 
	 * @throws MemoryAccessException 
	 * 
	 */
	PseudoDataComponent(Program program, Address address, PseudoData parent,
			DataTypeComponent component, MemBuffer memBuffer)
					throws AddressOverflowException, MemoryAccessException {
		super(program, address, component.getDataType(), new WrappedMemBuffer(memBuffer,
			component.getOffset()));
		this.indexInParent = component.getOrdinal();
		this.parent = parent;
		this.component = component;
		this.level = parent.level + 1;
		this.offset = component.getOffset();
		this.length = component.getLength();
	}

	PseudoDataComponent(Program program, Address address, PseudoData parent, DataType dt,
			int ordinal, int offset, int length, MemBuffer memBuffer)
			throws AddressOverflowException {
		super(program, address, dt, new WrappedMemBuffer(memBuffer, offset));
		this.indexInParent = ordinal;
		this.parent = parent;
		this.offset = offset;
		this.level = parent.level + 1;
		this.length = length;
	}

	/**
	 * 
	 * @see ghidra.program.model.listing.Data#getComponentPath()
	 */
	@Override
	public int[] getComponentPath() {
		if (path == null) {
			path = new int[level];
			int parentLevel = level - 1;
			path[parentLevel--] = indexInParent;

			Data parentData = parent;
			while (parentData instanceof PseudoDataComponent) {
				PseudoDataComponent dc = (PseudoDataComponent) parentData;
				path[parentLevel--] = dc.indexInParent;
				parentData = dc.parent;
			}
		}
		return path;
	}

	/**
	 * Get the name of this Data that is a component of another
	 * Data Item.
	 * @return the name as a component of another prototype,
	 *         and null if this is not a component of another prototype.
	 */
	@Override
	public String getFieldName() {
		if (component == null) { // is array?
			return "[" + this.indexInParent + "]";
		}
		String myName = component.getFieldName();

		// if the name is blank, look up in sym table for any references
		if (myName == null || myName.length() == 0) {
			myName = "field" + component.getOffset();
		}
		return myName;
	}

	/**
	 * Returns the path name (dot notation) for this field
	 */
	@Override
	public String getPathName() {
		String parentPath = parent.getPathName();
		return getComponentName(parentPath);
	}

	/**
	 * @return the relative path name (dot notation) for this field
	 */
	@Override
	public String getComponentPathName() {
		String parentPath = parent.getComponentPathName();
		return getComponentName(parentPath);
	}

	private String getComponentName(String parentPath) {
		StringBuffer nameBuffer = new StringBuffer();
		if (parentPath != null && parentPath.length() > 0) {
			nameBuffer.append(parentPath);
			if (component != null) { // not an array?
				nameBuffer.append('.');
			}
		}
		String myName = getFieldName();
		if (myName == null || myName.length() <= 0) {
			nameBuffer.append("field");
			nameBuffer.append(component.getOffset());
		}
		else {
			nameBuffer.append(myName);
		}
		return nameBuffer.toString();
	}

	/**
	 * Get the immediate parent Data Prototype of this component
	 */
	@Override
	public Data getParent() {
		return parent;
	}

	/**
	 * Get the highest level Data Prototype in a hierarchy of structures
	 * containing this component.
	 */
	@Override
	public Data getRoot() {
		return parent.getRoot();
	}

	/**
	 * Get the offset of this Data item from the start of
	 *  some hierarchy of structures.
	 */
	@Override
	public int getRootOffset() {
		return parent.getRootOffset() + getParentOffset();
	}

	/**
	 * Get the offset of this Data item from the start of its immediate
	 * parent.
	 */
	@Override
	public int getParentOffset() {
		return offset;
	}

	/**
	 * Get the index of this Data item within its parent
	 *
	 * @return the index of this component in its parent
	 *         returns -1 if this is not a component
	 */
	@Override
	public int getComponentIndex() {
		return indexInParent;
	}

	/**
	 * Returns whether some other object is "equal to" this one.
	 */
	@Override
	public boolean equals(Object obj) {

		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (obj.getClass() != PseudoDataComponent.class) {
			return false;
		}
		PseudoDataComponent data = (PseudoDataComponent) obj;
		if ((indexInParent != data.indexInParent) || (offset != data.offset)) {
			return false;
		}
		return super.equals(obj);
	}

	/**
	 * @see ghidra.docking.settings.Settings#getByteArray(java.lang.String)
	 */
	@Override
	public byte[] getByteArray(String name) {
		if (dataMgr == null) {
			return null;
		}
		byte[] settingBytes = dataMgr.getByteSettingsValue(address, name);
		if (settingBytes != null) {
			return settingBytes;
		}
		if (component == null) {
			return null;
		}
		if (defaultSettings == null) {
			defaultSettings = component.getDefaultSettings();
		}
		return defaultSettings.getByteArray(name);
	}

	/**
	 * @see ghidra.docking.settings.Settings#getLong(java.lang.String)
	 */
	@Override
	public Long getLong(String name) {
		if (dataMgr == null) {
			return null;
		}
		Long value = dataMgr.getLongSettingsValue(address, name);
		if (value != null) {
			return value;
		}
		if (component == null) {
			return null;
		}
		if (defaultSettings == null) {
			defaultSettings = component.getDefaultSettings();
		}
		return defaultSettings.getLong(name);
	}

	/**
	 * @see ghidra.docking.settings.Settings#getString(java.lang.String)
	 */
	@Override
	public String getString(String name) {
		if (dataMgr == null) {
			return null;
		}
		String value = dataMgr.getStringSettingsValue(address, name);
		if (value != null) {
			return value;
		}
		if (component == null) {
			return null;
		}
		if (defaultSettings == null) {
			defaultSettings = component.getDefaultSettings();
		}
		return defaultSettings.getString(name);
	}

	/**
	 * @see ghidra.docking.settings.Settings#getValue(java.lang.String)
	 */
	@Override
	public Object getValue(String name) {
		if (dataMgr == null) {
			return null;
		}
		Object value = dataMgr.getSettings(address, name);
		if (value != null) {
			return value;
		}
		if (component == null) {
			return null;
		}
		if (defaultSettings == null) {
			defaultSettings = component.getDefaultSettings();
		}
		return defaultSettings.getValue(name);
	}

	/**
	 * @see ghidra.program.model.listing.CodeUnit#getComment(int)
	 */
	@Override
	public synchronized String getComment(int commentType) {
		String cmt = super.getComment(commentType);
		if (cmt == null && commentType == CodeUnit.EOL_COMMENT && component != null) {
			cmt = component.getComment();
		}
		return cmt;
	}

	/**
	 * @see ghidra.docking.settings.Settings#getDefaultSettings()
	 */
	@Override
	public Settings getDefaultSettings() {
		if (component != null) {
			return component.getDefaultSettings();
		}
		return dataType.getDefaultSettings();
	}

}
