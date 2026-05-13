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
import ghidra.app.util.bin.format.objc.objc1.Objc1Constants;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class Objc2Class extends ObjcTypeMetadataStructure {
	public final static String NAME = "class_t";

	private Objc2Class isa;
	private Objc2Class superclass;
	private Objc2Cache cache;
	private Objc2Implementation vtable;
	private Objc2ClassRW data; // class_rw_t * plus custom rr/alloc flags

	public Objc2Class(Program program, ObjcState state, BinaryReader reader) {
		super(program, state, reader.getPointerIndex());

		state.classIndexMap.put(base, this);

		// TODO: Some class references point to a GOT entry. These aren't real class structures, 
		// so don't  parse them.

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
		if (that instanceof Objc2Class) {
			return this.base == ((Objc2Class) that).base;
		}
		return false;
	}

	@Override
	public int hashCode() {
		return (int) base;
	}

	public Objc2Class getISA() {
		return isa;
	}

	public Objc2Class getSuperClass() {
		return superclass;
	}

	public Objc2Cache getCache() {
		return cache;
	}

	public Objc2Implementation getVTable() {
		return vtable;
	}

	public Objc2ClassRW getData() {
		return data;
	}

	public long getIndex() {
		return base;
	}

	private void readData(BinaryReader reader) throws IOException {
		long index = 0;
		try {
			index = ObjcUtils.readNextIndex(reader, is32bit);
		}
		catch (IOException ioe) {
			//Trying to read uninitialized memory
			return;
		}

		// Fix pointer by applying Swift FAST_DATA_MASK (see objc-runtime-new.h for details)
		index &= is32bit ? ~0x3L : ~0x7L;

		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			data = new Objc2ClassRW(program, state, reader);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readVTable(BinaryReader reader) {
		try {
			vtable = new Objc2Implementation(program, state, reader);
		}
		catch (IOException ioe) {
			//Trying to read uninitialized memory
		}
	}

	private void readCache(BinaryReader reader) {
		try {
			cache = new Objc2Cache(program, state, reader);
		}
		catch (IOException ioe) {
			//Trying to read uninitialized memory
		}
	}

	private void readSuperClass(BinaryReader reader) {
		long index = 0;
		try {
			index = ObjcUtils.readNextIndex(reader, is32bit);
		}
		catch (IOException ioe) {
			//Trying to read uninitialized memory
			return;
		}

		if (state.classIndexMap.containsKey(index)) {
			superclass = state.classIndexMap.get(index);
			return;
		}

		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			superclass = new Objc2Class(program, state, reader);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readISA(BinaryReader reader) {
		long index = 0;
		try {
			index = ObjcUtils.readNextIndex(reader, is32bit);
		}
		catch (IOException ioe) {
			//Trying to read uninitialized memory
			return;
		}

		if (state.classIndexMap.containsKey(index)) {
			isa = state.classIndexMap.get(index);
			return;
		}

		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			isa = new Objc2Class(program, state, reader);
			reader.setPointerIndex(originalIndex);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(NAME, 0);

		struct.add(new PointerDataType(struct), pointerSize, "isa", null);
		struct.add(new PointerDataType(struct), pointerSize, "superclass", null);
		struct.add(cache.toDataType(), "cache", null);
		struct.add(vtable.toDataType(), "vtable", null);

		if (data == null) {
			Objc2ClassRW fakeData = new Objc2ClassRW(program, state);
			struct.add(new PointerDataType(fakeData.toDataType()), pointerSize, "data", null);
		}
		else {
			struct.add(new PointerDataType(data.toDataType()), pointerSize, "data", null);
		}

		struct.setCategoryPath(Objc2Constants.CATEGORY_PATH);
		return struct;
	}

	@Override
	public void applyTo(Namespace namespace, TaskMonitor monitor) throws Exception {
		if (state.beenApplied.contains(base)) {//handle circular references
			return;
		}
		state.beenApplied.add(base);

		Address address = ObjcUtils.toAddress(program, getIndex());
		try {
			ObjcUtils.createData(program, toDataType(), address);
		}
		catch (Exception e) {
			// do nothing
		}

		try {
			Namespace classNamespace =
				ObjcUtils.createNamespace(program, Objc1Constants.NAMESPACE, Objc2Class.NAME);
			ObjcUtils.createSymbol(program, classNamespace, data.getName(), address);
		}
		catch (Exception e) {
			// do nothing
		}

		if (isa != null) {
			isa.applyTo(namespace, monitor);
		}
		if (superclass != null) {
			superclass.applyTo(namespace, monitor);
		}
		if (cache != null) {
			cache.applyTo(namespace, monitor);
		}
		if (vtable != null) {
			vtable.applyTo(namespace, monitor);
		}
		if (data != null) {
			data.applyTo(namespace, monitor);
		}
	}
}
