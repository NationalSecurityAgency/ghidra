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
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.WrappedMemBuffer;

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

	PseudoDataComponent(Program program, Address address, PseudoData parent,
			DataTypeComponent component, MemBuffer memBuffer)
			throws AddressOverflowException {
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
		if (obj.getClass() != PseudoDataComponent.class) {
			return false;
		}
		PseudoDataComponent data = (PseudoDataComponent) obj;
		if ((indexInParent != data.indexInParent) || (offset != data.offset)) {
			return false;
		}
		return super.equals(obj);
	}

	@Override
	public synchronized String getComment(int commentType) {
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
