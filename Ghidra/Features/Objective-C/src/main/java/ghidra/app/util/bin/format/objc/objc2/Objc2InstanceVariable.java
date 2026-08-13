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
package ghidra.app.util.bin.format.objc.objc2;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.objc.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class Objc2InstanceVariable extends ObjcTypeMetadataStructure {
	private long offset;
	private String name;
	private String type;
	private int alignment;
	private int size;

	public Objc2InstanceVariable(Program program, ObjcState state, BinaryReader reader)
			throws IOException {
		super(program, state, reader.getPointerIndex());

		offset = ObjcUtils.readNextIndex(reader, is32bit);

		long nameIndex = ObjcUtils.readNextIndex(reader, is32bit);
		if (nameIndex > 0 && reader.isValidIndex(nameIndex)) {
			name = reader.readAsciiString(nameIndex);
		}

		long typeIndex = ObjcUtils.readNextIndex(reader, is32bit);
		if (typeIndex > 0 && reader.isValidIndex(typeIndex)) {
			type = reader.readAsciiString(typeIndex);
		}

		alignment = reader.readNextInt();
		size = reader.readNextInt();
	}

	public long getOffset() {
		return offset;
	}

	public String getName() {
		return name;
	}

	public String getType() {
		return type;
	}

	public int getAlignment() {
		return alignment;
	}

	public int getSize() {
		return size;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType("ivar_t", 0);
		if (is32bit) {
			struct.add(new PointerDataType(DWORD), pointerSize, "offset", null);
			struct.add(new PointerDataType(STRING), pointerSize, "name", null);
			struct.add(new PointerDataType(STRING), pointerSize, "type", null);
		}
		else {
			struct.add(new PointerDataType(QWORD), pointerSize, "offset", null);
			struct.add(new PointerDataType(STRING), pointerSize, "name", null);
			struct.add(new PointerDataType(STRING), pointerSize, "type", null);
		}
		struct.add(DWORD, "alignment", null);
		struct.add(DWORD, "size", null);
		struct.setCategoryPath(Objc2Constants.CATEGORY_PATH);
		return struct;
	}

	@Override
	public void applyTo(Namespace namespace, TaskMonitor monitor) throws Exception {
		if (getOffset() == 0) {
			return;
		}
		if (getName() == null && getName().length() == 0) {
			return;
		}
		Address address =
			program.getAddressFactory().getDefaultAddressSpace().getAddress(getOffset());
		ObjcUtils.createSymbol(program, namespace, getName(), address);
		state.variableMap.put(address, this);
	}
}
