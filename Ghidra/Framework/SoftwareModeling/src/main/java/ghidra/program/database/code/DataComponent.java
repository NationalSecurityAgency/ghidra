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
package ghidra.program.database.code;

import db.DBRecord;
import ghidra.docking.settings.Settings;
import ghidra.program.database.DBObjectCache;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * <code>DataComponent</code> provides Data and CodeUnit access to Struct and Array components.
 *
 * NOTE!! DataComponents only have a unique key within its parent Struct/Array.  This places a constraint on
 * the use of the key field and getKey() method on the underlying classes CodeUnitDB and DataDB.
 * The CodeUnit key should only be used for managing an object cache.
 */
class DataComponent extends DataDB {

	DataDB parent;
	DataTypeComponent component;
	private int indexInParent;
	private int offset;
	private int[] path;

	/**
	 * Constructs a new {@link DataComponent} for a {@link DataTypeComponent}.
	 * NOTE: a zero-length component will be forced to have a length of 1-byte.
	 * This can result in what would appear to be overlapping components with the same overset.
	 * @param codeMgr the code manager.
	 * @param componentCache data component cache
	 * @param address the address of the data component
	 * @param addr the convert address long value
	 * @param parent the DataDB object that contains this component.
	 * @param component the DataTypeComponent for this DataComponent.
	 */
	public DataComponent(CodeManager codeMgr, DBObjectCache<DataDB> componentCache, Address address,
			long addr, DataDB parent, DataTypeComponent component) {
		super(codeMgr, componentCache, component.getOrdinal(), address, addr,
			component.getDataType());
		this.indexInParent = component.getOrdinal();
		this.parent = parent;
		this.component = component;
		this.level = parent.level + 1;
		this.offset = component.getOffset();
		length = component.getLength();
		if (length == 0) {
			length = 1; // zero-length components must be forced to have a length of 1
		}
	}

	/**
	 * Constructs a new {@link DataComponent} for an {@link Array} element.
	 * @param codeMgr the code manager.
	 * @param componentCache data component cache
	 * @param address the address of the data component
	 * @param addr the convert address long value
	 * @param parent the DataDB object that contains this component.
	 * @param array the array containing this component.
	 * @param ordinal the array index for this component.
	 */
	DataComponent(CodeManager codeMgr, DBObjectCache<DataDB> componentCache, Address address,
			long addr, DataDB parent, Array array, int ordinal) {
		super(codeMgr, componentCache, ordinal, address, addr, array.getDataType());
		int elementLength = array.getElementLength();
		this.indexInParent = ordinal;
		this.parent = parent;
		this.offset = ordinal * elementLength;
		this.level = parent.level + 1;
		this.length = elementLength;
	}

	@Override
	protected boolean hasBeenDeleted(DBRecord rec) {
		// Records do not apply to data components which
		// are derived from parent data type
		if (parent.hasBeenDeleted(null)) {
			return true;
		}
		DataType pdt = parent.getBaseDataType();
		if (pdt instanceof Composite) {
			Composite composite = (Composite) pdt;
			// if we are deleted, the parent may not have as many components as it used to,
			// so if our index is bigger than the number of components, then we are deleted.
			if (indexInParent >= composite.getNumComponents()) {
				return true;
			}
			DataTypeComponent c = composite.getComponent(indexInParent);
			component = c;
			dataType = c.getDataType();
			offset = component.getOffset();
			length = component.getLength();
			if (length == 0) {
				length = 1; // zero-length components must be forced to have a length of 1
			}
		}
		else if (pdt instanceof Array) {
			Array a = (Array) pdt;
			if (indexInParent >= a.getNumElements()) {
				return true;
			}
			component = null;
			dataType = ((Array) pdt).getDataType();
			length = a.getElementLength();
			offset = length * indexInParent;
		}
		else {
			return true;
		}
		address = parent.getAddress().add(offset);
		addr = parent.addr + offset;
		baseDataType = getBaseDataType(dataType);
		bytes = null;
		return false;
	}

	@Override
	public int[] getComponentPath() {
		if (path == null) {
			path = new int[level];
			int parentLevel = level - 1;
			path[parentLevel--] = indexInParent;

			Data parentData = parent;
			while (parentData instanceof DataComponent) {
				DataComponent dc = (DataComponent) parentData;
				path[parentLevel--] = dc.indexInParent;
				parentData = dc.parent;
			}
		}
		return path;
	}

	@Override
	public String getFieldName() {
		if (component == null) { // is array?
			return "[" + this.indexInParent + "]";
		}
		String myName = component.getFieldName();
		if (myName == null || myName.length() == 0) {
			myName = component.getDefaultFieldName();
		}
		return myName;
	}

	@Override
	public String getPathName() {
		String parentPath = parent.getPathName();
		return getComponentName(parentPath);
	}

	@Override
	public String getComponentPathName() {
		String parentPath = parent.getComponentPathName();
		return getComponentName(parentPath);
	}

	private String getComponentName(String parentPath) {
		StringBuffer stringBuffer = new StringBuffer();
		if (parentPath != null && parentPath.length() > 0) {
			stringBuffer.append(parentPath);
			if (component != null) { // not an array?
				stringBuffer.append('.');
			}
		}
		String myName = getFieldName();
		stringBuffer.append(myName);
		return stringBuffer.toString();
	}

	@Override
	public Data getParent() {
		return parent;
	}

	@Override
	public Data getRoot() {
		return parent.getRoot();
	}

	@Override
	public int getRootOffset() {
		return parent.getRootOffset() + getParentOffset();
	}

	@Override
	public int getParentOffset() {
		return offset;
	}

	@Override
	public int getComponentIndex() {
		return indexInParent;
	}

	@Override
	public boolean equals(Object obj) {

		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (obj.getClass() != DataComponent.class) {
			return false;
		}
		DataComponent data = (DataComponent) obj;
		if ((indexInParent != data.indexInParent) || (offset != data.offset)) {
			return false;
		}
		return super.equals(obj);
	}

	@Override
	protected int getPreferredCacheLength() {
		return 0; // rely on parent for cached bytes
	}

	@Override
	public int getBytes(byte[] b, int offset) {
		lock.acquire();
		try {
			checkIsValid();
			return parent.getBytes(b, this.offset + offset);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public byte[] getBytes() throws MemoryAccessException {
		lock.acquire();
		try {
			checkIsValid();
			byte[] b = new byte[length];
			if (parent.getBytes(b, this.offset) != length) {
				throw new MemoryAccessException("Couldn't get all bytes for CodeUnit");
			}
			return b;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public byte getByte(int n) throws MemoryAccessException {
		lock.acquire();
		try {
			checkIsValid();
			return parent.getByte(this.offset + n);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public String getComment(int commentType) {
		String cmt = super.getComment(commentType);
		if (cmt == null && commentType == CodeUnit.EOL_COMMENT && component != null) {
			cmt = component.getComment();
		}
		return cmt;
	}

	@Override
	public Settings getDefaultSettings() {
		if (component != null) {
			return component.getDefaultSettings();
		}
		return super.getDefaultSettings();
	}

}
