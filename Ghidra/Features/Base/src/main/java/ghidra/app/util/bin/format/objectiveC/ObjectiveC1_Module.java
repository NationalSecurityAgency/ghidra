/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.objectiveC;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class ObjectiveC1_Module implements StructConverter {
	private ObjectiveC1_State _state;
	private long _index;

	private int version;
	private int size;
	private String name;
	private ObjectiveC1_SymbolTable symbolTable;

	public ObjectiveC1_Module(ObjectiveC1_State state, BinaryReader reader) throws IOException {
		this._state = state;
		_index = reader.getPointerIndex();

		version = reader.readNextInt();
		size = reader.readNextInt();
		name = ObjectiveC1_Utilities.dereferenceAsciiString(reader, state.is32bit);

		int symbolTableIndex = reader.readNextInt();

		if (symbolTableIndex != 0) {
			symbolTable = new ObjectiveC1_SymbolTable(state, reader.clone(symbolTableIndex));
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

	public ObjectiveC1_SymbolTable getSymbolTable() {
		return symbolTable;
	}

	public void applyTo() throws Exception {
		if (_state.beenApplied.contains(_index)) {
			return;
		}
		_state.beenApplied.add(_index);

		Address address =
			_state.program.getAddressFactory().getDefaultAddressSpace().getAddress(_index);
		DataType dt = toDataType();
		try {
			_state.program.getListing().createData(address, dt);
		}
		catch (Exception e) {
		}

		if (symbolTable != null) {
			symbolTable.applyTo();
		}
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("objc_module", 0);
		struct.setCategoryPath(ObjectiveC1_Constants.CATEGORY_PATH);
		struct.add(DWORD, "version", null);
		struct.add(DWORD, "size", null);
		struct.add(PointerDataType.getPointer(ASCII, _state.pointerSize), "name", null);
		struct.add(PointerDataType.getPointer(ObjectiveC1_SymbolTable.toGenericDataType(),
			_state.pointerSize), "symtab", null);
		return struct;
	}
}
