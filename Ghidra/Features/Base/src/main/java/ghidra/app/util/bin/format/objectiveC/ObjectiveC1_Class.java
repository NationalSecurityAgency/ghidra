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
package ghidra.app.util.bin.format.objectiveC;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class ObjectiveC1_Class implements StructConverter {
	public final static String NAME = "objc_class";
	public static final long SIZEOF = 0x30;

	private ObjectiveC1_State _state;
	private long _index;

	private ObjectiveC1_MetaClass isa;
	private String super_class;
	private String name;
	private int version;
	private int info;
	private int instance_size;
	private ObjectiveC1_InstanceVariableList variable_list;
	private ObjectiveC1_MethodList method_list;
	private int cache;
	private ObjectiveC1_ProtocolList protocols;
	private int unknown0;
	private int unknown1;

	public ObjectiveC1_Class(ObjectiveC1_State state, BinaryReader reader) throws IOException {
		this._state = state;
		this._index = reader.getPointerIndex();

		isa = new ObjectiveC1_MetaClass(state, reader.clone(reader.readNextInt()));
		super_class = ObjectiveC1_Utilities.dereferenceAsciiString(reader, state.is32bit);
		name = reader.readAsciiString(reader.readNextInt());
		version = reader.readNextInt();
		info = reader.readNextInt();
		instance_size = reader.readNextInt();
		variable_list =
			new ObjectiveC1_InstanceVariableList(state, reader.clone(reader.readNextInt()));
		method_list =
			new ObjectiveC1_MethodList(state, reader.clone(reader.readNextInt()),
				ObjectiveC_MethodType.INSTANCE);
		cache = reader.readNextInt();
		protocols = new ObjectiveC1_ProtocolList(state, reader.clone(reader.readNextInt()));
		unknown0 = reader.readNextInt();
		unknown1 = reader.readNextInt();
	}

	public ObjectiveC1_MetaClass getISA() {
		return isa;
	}

	public String getSuperClass() {
		return super_class;
	}

	public String getName() {
		return name;
	}

	public int getVersion() {
		return version;
	}

	public int getInfo() {
		return info;
	}

	public int getInstanceSize() {
		return instance_size;
	}

	public ObjectiveC1_InstanceVariableList getInstanceVariableList() {
		return variable_list;
	}

	public ObjectiveC1_MethodList getMethodList() {
		return method_list;
	}

	public int getCache() {
		return cache;
	}

	public ObjectiveC1_ProtocolList getProtocols() {
		return protocols;
	}

	public int getUnknown0() {
		return unknown0;
	}

	public int getUnknown1() {
		return unknown1;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.setCategoryPath(ObjectiveC1_Constants.CATEGORY_PATH);
		struct.add(PointerDataType.getPointer(isa.toDataType(), _state.pointerSize), "isa", null);
		struct.add(PointerDataType.getPointer(ASCII, _state.pointerSize), "super_class", null);
		struct.add(PointerDataType.getPointer(ASCII, _state.pointerSize), "name", null);
		struct.add(DWORD, "version", null);
		struct.add(DWORD, "info", null);
		struct.add(DWORD, "instance_size", null);
		struct.add(PointerDataType.getPointer(ObjectiveC1_InstanceVariableList.toGenericDataType(),
			_state.pointerSize), "instance_vars", null);
		struct.add(PointerDataType.getPointer(ObjectiveC1_MethodList.toGenericDataType(_state),
			_state.pointerSize), "method_lists", null);
		struct.add(DWORD, "cache", null);
		struct.add(PointerDataType.getPointer(ObjectiveC1_ProtocolList.toGenericDataType(_state),
			_state.pointerSize), "protocols", null);
		struct.add(DWORD, "unknown0", null);
		struct.add(DWORD, "unknown1", null);
		return struct;
	}

	public void applyTo() throws Exception {
		Address address =
			_state.program.getAddressFactory().getDefaultAddressSpace().getAddress(_index);
		DataType dt = toDataType();
		_state.program.getListing().clearCodeUnits(address, address.add(dt.getLength() - 1), false);
		_state.program.getListing().createData(address, dt);
		_state.program.getSymbolTable().createLabel(address, "objc_class_" + name,
			SourceType.ANALYSIS);

		Namespace namespace = ObjectiveC1_Utilities.getClassNamespace(_state.program, null, name);

		isa.applyTo();
		variable_list.applyTo();
		method_list.applyTo(namespace);

		//don't do protocols here... they are applied independent
	}
}
