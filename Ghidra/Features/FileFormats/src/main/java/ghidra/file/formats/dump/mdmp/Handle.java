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
package ghidra.file.formats.dump.mdmp;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.dump.DumpFileReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class Handle implements StructConverter {

	public final static String NAME = "MINIDUMP_HANDLE";

	private long handle;
	private int typeNameRVA;
	private int objectNameRVA;
	private int attributes;
	private int GrantedAccess;
	private int HandleCount;
	private int PointerCount;
	private int ObjectInfoRva;

	private DumpFileReader reader;
	private long index;
	private int entrySize;
	private boolean expandedFormat;

	Handle(DumpFileReader reader, long index, int entrySize) throws IOException {
		this.reader = reader;
		this.index = index;
		this.entrySize = entrySize;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setHandle(reader.readNextLong());
		setTypeNameRVA(reader.readNextInt());
		setObjectNameRVA(reader.readNextInt());
		setAttributes(reader.readNextInt());
		setGrantedAccess(reader.readNextInt());
		setHandleCount(reader.readNextInt());
		setPointerCount(reader.readNextInt());
		expandedFormat = entrySize > reader.getPointerIndex() - index;
		if (expandedFormat) {
			setObjectInfoRva(reader.readNextInt());
			reader.readNextInt();
		}

	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(QWORD, 8, "Handle", null);
		struct.add(Pointer32DataType.dataType, 4, "TypeNameRVA", null);
		struct.add(Pointer32DataType.dataType, 4, "ObjectNameRVA", null);
		struct.add(DWORD, 4, "Attributes", null);
		struct.add(DWORD, 4, "GrantedAccess", null);
		struct.add(DWORD, 4, "HandleCount", null);
		struct.add(DWORD, 4, "PointerCount", null);
		if (expandedFormat) {
			struct.add(Pointer32DataType.dataType, 4, "ObjectInfoRva", null);
			struct.add(DWORD, 4, "Reserved0", null);
		}

		struct.setCategoryPath(new CategoryPath("/MDMP"));

		return struct;
	}

	public long getHandle() {
		return handle;
	}

	public void setHandle(long handle) {
		this.handle = handle;
	}

	public int getTypeNameRVA() {
		return typeNameRVA;
	}

	public void setTypeNameRVA(int typeNameRVA) {
		this.typeNameRVA = typeNameRVA;
	}

	public int getObjectNameRVA() {
		return objectNameRVA;
	}

	public void setObjectNameRVA(int objectNameRVA) {
		this.objectNameRVA = objectNameRVA;
	}

	public int getAttributes() {
		return attributes;
	}

	public void setAttributes(int attributes) {
		this.attributes = attributes;
	}

	public int getGrantedAccess() {
		return GrantedAccess;
	}

	public void setGrantedAccess(int grantedAccess) {
		GrantedAccess = grantedAccess;
	}

	public int getHandleCount() {
		return HandleCount;
	}

	public void setHandleCount(int handleCount) {
		HandleCount = handleCount;
	}

	public int getPointerCount() {
		return PointerCount;
	}

	public void setPointerCount(int pointerCount) {
		PointerCount = pointerCount;
	}

	public int getObjectInfoRva() {
		return ObjectInfoRva;
	}

	public void setObjectInfoRva(int objectInfoRva) {
		ObjectInfoRva = objectInfoRva;
	}
}
