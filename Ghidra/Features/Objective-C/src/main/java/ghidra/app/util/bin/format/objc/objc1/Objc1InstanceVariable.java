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
package ghidra.app.util.bin.format.objc.objc1;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.objc.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class Objc1InstanceVariable extends ObjcTypeMetadataStructure {
	private String name;
	private String type;
	private int offset;

	Objc1InstanceVariable(Program program, ObjcState state, BinaryReader reader)
			throws IOException {
		super(program, state, reader.getPointerIndex());

		name = ObjcUtils.dereferenceAsciiString(reader, is32bit);
		type = ObjcUtils.dereferenceAsciiString(reader, is32bit);
		offset = reader.readNextInt();
	}

	public String getName() {
		return name;
	}

	public String getType() {
		return type;
	}

	public int getOffset() {
		return offset;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("objc_ivar", 0);
		struct.setCategoryPath(Objc1Constants.CATEGORY_PATH);
		struct.add(PointerDataType.getPointer(ASCII, pointerSize), "ivar_name", null);
		struct.add(PointerDataType.getPointer(ASCII, pointerSize), "ivar_type", null);
		struct.add(DWORD, "ivar_offset", null);
		return struct;
	}

	@Override
	public void applyTo(Namespace namespace, TaskMonitor monitor) throws Exception {
		if (state.beenApplied.contains(base)) {
			return;
		}
		state.beenApplied.add(base);

		Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(base);
		DataType dt = toDataType();
		program.getListing().clearCodeUnits(address, address.add(dt.getLength() - 1), false);
		program.getListing().createData(address, dt);
	}
}
