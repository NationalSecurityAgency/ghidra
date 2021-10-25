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
package ghidra.app.util.bin.format.objc2;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.macho.SectionNames;
import ghidra.app.util.bin.format.objectiveC.ObjectiveC1_Constants;
import ghidra.app.util.bin.format.objectiveC.ObjectiveC1_Utilities;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.DuplicateNameException;

public class ObjectiveC2_Class implements StructConverter {
	public final static String NAME = "class_t";

	private ObjectiveC2_State _state;
	private long _index;

	private ObjectiveC2_Class isa;
	private ObjectiveC2_Class superclass;
	private ObjectiveC2_Cache cache;
	private ObjectiveC2_Implementation vtable;
	private ObjectiveC2_ClassRW data;

	public ObjectiveC2_Class(ObjectiveC2_State state, BinaryReader reader) {
		this._state = state;
		this._index = reader.getPointerIndex();

		state.classIndexMap.put(_index, this);
		
		// Some class references point to a GOT entry. These aren't real class structures, so don't 
		// parse them.
		AddressSpace space = _state.program.getAddressFactory().getDefaultAddressSpace();
		Address addr = space.getAddress(_index);
		Symbol symbol = _state.program.getSymbolTable().getPrimarySymbol(addr);
		if (symbol.getParentNamespace().getName().equals(SectionNames.SECT_GOT)) {
			return;
		}

		try {
			readISA(reader);
			readSuperClass(reader);
			readCache(reader);
			readVTable(reader);
			readData(reader);
		}
		catch (IOException ioe) {
			// Couldn't read something, usually a metaclass pointing to an uninitialized section since
			// runtime 2.0 got rid of the metaclass type.
		}
	}

	@Override
	public boolean equals(Object that) {
		if (that instanceof ObjectiveC2_Class) {
			return this._index == ((ObjectiveC2_Class) that)._index;
		}
		return false;
	}

	@Override
	public int hashCode() {
		return (int) _index;
	}

	public ObjectiveC2_Class getISA() {
		return isa;
	}

	public ObjectiveC2_Class getSuperClass() {
		return superclass;
	}

	public ObjectiveC2_Cache getCache() {
		return cache;
	}

	public ObjectiveC2_Implementation getVTable() {
		return vtable;
	}

	public ObjectiveC2_ClassRW getData() {
		return data;
	}

	public long getIndex() {
		return _index;
	}

	private void readData(BinaryReader reader) throws IOException {
		long index = 0;
		try {
			index = ObjectiveC1_Utilities.readNextIndex(reader, _state.is32bit);
		}
		catch (IOException ioe) {
			//Trying to read uninitialized memory
			return;
		}
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			data = new ObjectiveC2_ClassRW(_state, reader);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readVTable(BinaryReader reader) {
		try {
			vtable = new ObjectiveC2_Implementation(_state, reader);
		}
		catch (IOException ioe) {
			//Trying to read uninitialized memory
		}
	}

	private void readCache(BinaryReader reader) {
		try {
			cache = new ObjectiveC2_Cache(_state, reader);
		}
		catch (IOException ioe) {
			//Trying to read uninitialized memory
		}
	}

	private void readSuperClass(BinaryReader reader) throws IOException {
		long index = 0;
		try {
			index = ObjectiveC1_Utilities.readNextIndex(reader, _state.is32bit);
		}
		catch (IOException ioe) {
			//Trying to read uninitialized memory
			return;
		}

		if (_state.classIndexMap.containsKey(index)) {
			superclass = _state.classIndexMap.get(index);
			return;
		}

		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			superclass = new ObjectiveC2_Class(_state, reader);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readISA(BinaryReader reader) throws IOException {
		long index = 0;
		try {
			index = ObjectiveC2_Utilities.readNextIndex(reader, _state.is32bit);
		}
		catch (IOException ioe) {
			//Trying to read uninitialized memory
			return;
		}

		if (_state.classIndexMap.containsKey(index)) {
			isa = _state.classIndexMap.get(index);
			return;
		}

		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			isa = new ObjectiveC2_Class(_state, reader);
			reader.setPointerIndex(originalIndex);
		}
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(NAME, 0);

		struct.add(new PointerDataType(struct), _state.pointerSize, "isa", null);
		struct.add(new PointerDataType(struct), _state.pointerSize, "superclass", null);
		struct.add(cache.toDataType(), "cache", null);
		struct.add(vtable.toDataType(), "vtable", null);

		if (data == null) {
			ObjectiveC2_ClassRW fakeData = new ObjectiveC2_ClassRW();
			struct.add(new PointerDataType(fakeData.toDataType()), _state.pointerSize, "data", null);
		}
		else {
			struct.add(new PointerDataType(data.toDataType()), _state.pointerSize, "data", null);
		}

		struct.setCategoryPath(ObjectiveC2_Constants.CATEGORY_PATH);
		return struct;
	}

	public void applyTo() throws Exception {
		if (_state.beenApplied.contains(_index)) {//handle circular references
			return;
		}
		_state.beenApplied.add(_index);

		Address address = ObjectiveC1_Utilities.toAddress(_state.program, getIndex());
		try {
			ObjectiveC1_Utilities.applyData(_state.program, toDataType(), address);
		}
		catch (Exception e) {
		}

		try {
			Namespace namespace =
				ObjectiveC1_Utilities.createNamespace(_state.program,
					ObjectiveC1_Constants.NAMESPACE, ObjectiveC2_Class.NAME);
			ObjectiveC1_Utilities.createSymbol(_state.program, namespace, data.getName(), address);
		}
		catch (Exception e) {
		}

		if (isa != null) {
			isa.applyTo();
		}
		if (superclass != null) {
			superclass.applyTo();
		}
		if (cache != null) {
			cache.applyTo();
		}
		if (vtable != null) {
			vtable.applyTo();
		}
		if (data != null) {
			data.applyTo();
		}
	}
}
