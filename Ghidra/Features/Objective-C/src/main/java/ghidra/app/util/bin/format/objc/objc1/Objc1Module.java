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
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class Objc1Module extends ObjcTypeMetadataStructure {
	private int version;
	private int size;
	private String name;
	private Objc1SymbolTable symbolTable;

	public Objc1Module(Program program, ObjcState state, BinaryReader reader) throws IOException {
		super(program, state, reader.getPointerIndex());

		version = reader.readNextInt();
		size = reader.readNextInt();
		name = ObjcUtils.dereferenceAsciiString(reader, is32bit);

		int symbolTableIndex = reader.readNextInt();

		if (symbolTableIndex != 0) {
			symbolTable = new Objc1SymbolTable(program, state, reader.clone(symbolTableIndex));
		}
	}

	public int getVersion() {
		return version;
	}

	public int getSize() {
		return size;
	}

	public String getName() {
		return name;
	}

	public Objc1SymbolTable getSymbolTable() {
		return symbolTable;
	}

	@Override
	public void applyTo(Namespace namespace, TaskMonitor monitor) throws Exception {
		if (state.beenApplied.contains(base)) {
			return;
		}
		state.beenApplied.add(base);

		Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(base);
		DataType dt = toDataType();
		try {
			DataUtilities.createData(program, address, dt, -1,
				ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
		}
		catch (Exception e) {
			Msg.warn(this, "Could not create " + dt.getName() + " @" + address);
		}

		if (symbolTable != null) {
			symbolTable.applyTo(namespace, monitor);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("objc_module", 0);
		struct.setCategoryPath(Objc1Constants.CATEGORY_PATH);
		struct.add(DWORD, "version", null);
		struct.add(DWORD, "size", null);
		struct.add(PointerDataType.getPointer(ASCII, pointerSize), "name", null);
		struct.add(PointerDataType.getPointer(Objc1SymbolTable.toGenericDataType(), pointerSize),
			"symtab", null);
		return struct;
	}
}
