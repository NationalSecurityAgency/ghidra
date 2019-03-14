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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.objectiveC.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.Conv;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class ObjectiveC2_Protocol implements StructConverter {
	public final static String NAME = "protocol_t";

	private ObjectiveC2_State _state;
	private long _index;

	private long isa;
	private String name;
	private ObjectiveC2_ProtocolList protocols;
	private ObjectiveC2_MethodList instanceMethods;
	private ObjectiveC2_MethodList classMethods;

	private ObjectiveC2_MethodList optionalInstanceMethods;
	private ObjectiveC2_MethodList optionalClassMethods;
	private ObjectiveC2_PropertyList instanceProperties;
	private long unknown0;
	private long unknown1;

	public ObjectiveC2_Protocol(ObjectiveC2_State state, BinaryReader reader) throws IOException {
		this._state = state;
		this._index = reader.getPointerIndex();

		isa = ObjectiveC1_Utilities.readNextIndex(reader, state.is32bit);//TODO
		readName(reader);
		readProtocols(reader);
		readInstanceMethods(reader);
		readClassMethods(reader);
		readOptionalInstanceMethods(reader);
		readOptionalClassMethods(reader);
		readInstanceProperties(reader);

		if (state.is32bit) {
			unknown0 = reader.readNextInt() & Conv.INT_MASK;
			unknown1 = reader.readNextInt() & Conv.INT_MASK;
		}
		else {
			unknown0 = reader.readNextLong();
			unknown1 = reader.readNextLong();
		}
	}

	public long getIsa() {
		return isa;
	}

	public String getName() {
		return name;
	}

	public ObjectiveC2_ProtocolList getProtocols() {
		return protocols;
	}

	public ObjectiveC2_MethodList getInstanceMethods() {
		return instanceMethods;
	}

	public ObjectiveC2_MethodList getClassMethods() {
		return classMethods;
	}

	public ObjectiveC2_MethodList getOptionalInstanceMethods() {
		return optionalInstanceMethods;
	}

	public ObjectiveC2_MethodList getOptionalClassMethods() {
		return optionalClassMethods;
	}

	public ObjectiveC2_PropertyList getInstanceProperties() {
		return instanceProperties;
	}

	public long getUnknown0() {
		return unknown0;
	}

	public long getUnknown1() {
		return unknown1;
	}

	public long getIndex() {
		return _index;
	}

	private void readProtocols(BinaryReader reader) throws IOException {
		long index = ObjectiveC1_Utilities.readNextIndex(reader, _state.is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			protocols = new ObjectiveC2_ProtocolList(_state, reader);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readName(BinaryReader reader) throws IOException {
		long index = ObjectiveC1_Utilities.readNextIndex(reader, _state.is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			name = reader.readAsciiString(index);
		}
	}

	private void readInstanceMethods(BinaryReader reader) throws IOException {
		long index = ObjectiveC1_Utilities.readNextIndex(reader, _state.is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			instanceMethods =
				new ObjectiveC2_MethodList(_state, reader, ObjectiveC_MethodType.INSTANCE);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readClassMethods(BinaryReader reader) throws IOException {
		long index = ObjectiveC1_Utilities.readNextIndex(reader, _state.is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			classMethods = new ObjectiveC2_MethodList(_state, reader, ObjectiveC_MethodType.CLASS);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readOptionalInstanceMethods(BinaryReader reader) throws IOException {
		long index = ObjectiveC1_Utilities.readNextIndex(reader, _state.is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			optionalInstanceMethods =
				new ObjectiveC2_MethodList(_state, reader, ObjectiveC_MethodType.INSTANCE);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readOptionalClassMethods(BinaryReader reader) throws IOException {
		long index = ObjectiveC1_Utilities.readNextIndex(reader, _state.is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			optionalClassMethods =
				new ObjectiveC2_MethodList(_state, reader, ObjectiveC_MethodType.CLASS);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readInstanceProperties(BinaryReader reader) throws IOException {
		long index = ObjectiveC1_Utilities.readNextIndex(reader, _state.is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			instanceProperties = new ObjectiveC2_PropertyList(_state, reader);
			reader.setPointerIndex(originalIndex);
		}
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(NAME, 0);

		if (_state.is32bit) {
			struct.add(DWORD, "isa", null);
		}
		else {
			struct.add(QWORD, "isa", null);
		}

		struct.add(new PointerDataType(STRING), _state.pointerSize, "name", null);
		struct.add(new PointerDataType(ObjectiveC2_ProtocolList.toGenericDataType(_state)),
			_state.pointerSize, "protocols", null);
		struct.add(new PointerDataType(ObjectiveC2_MethodList.toGenericDataType()),
			_state.pointerSize, "instanceMethods", null);
		struct.add(new PointerDataType(ObjectiveC2_MethodList.toGenericDataType()),
			_state.pointerSize, "classMethods", null);
		struct.add(new PointerDataType(ObjectiveC2_MethodList.toGenericDataType()),
			_state.pointerSize, "optionalInstanceMethods", null);
		struct.add(new PointerDataType(ObjectiveC2_MethodList.toGenericDataType()),
			_state.pointerSize, "optionalClassMethods", null);
		struct.add(new PointerDataType(ObjectiveC2_PropertyList.toGenericDataType()),
			_state.pointerSize, "instanceProperties", null);

		if (_state.is32bit) {
			struct.add(DWORD, "unknown0", null);
			struct.add(DWORD, "unknown1", null);
		}
		else {
			struct.add(QWORD, "unknown0", null);
			struct.add(QWORD, "unknown1", null);
		}

		struct.setCategoryPath(ObjectiveC2_Constants.CATEGORY_PATH);
		return struct;
	}

	public void applyTo(Namespace namespace) throws Exception {
		Address address = ObjectiveC1_Utilities.toAddress(_state.program, getIndex());
		try {
			ObjectiveC1_Utilities.applyData(_state.program, toDataType(), address);
		}
		catch (Exception e) {
		}

		try {
			Namespace protocolNamespace =
				ObjectiveC1_Utilities.createNamespace(_state.program,
					ObjectiveC1_Constants.NAMESPACE, ObjectiveC2_Protocol.NAME);
			ObjectiveC1_Utilities.createSymbol(_state.program, protocolNamespace, getName(),
				address);
		}
		catch (Exception e) {
		}

		if (protocols != null) {
			protocols.applyTo(namespace);
		}
		if (instanceMethods != null) {
			instanceMethods.applyTo(namespace);
		}
		if (classMethods != null) {
			classMethods.applyTo(namespace);
		}
		if (optionalInstanceMethods != null) {
			optionalInstanceMethods.applyTo(namespace);
		}
		if (optionalClassMethods != null) {
			optionalClassMethods.applyTo(namespace);
		}
		if (instanceProperties != null) {
			instanceProperties.applyTo(namespace);
		}
	}
}
