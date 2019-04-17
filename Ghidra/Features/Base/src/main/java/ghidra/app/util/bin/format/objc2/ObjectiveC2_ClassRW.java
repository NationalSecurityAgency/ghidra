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

public class ObjectiveC2_ClassRW implements StructConverter {
	public final static String NAME = "class_rw_t";

	private ObjectiveC2_State _state;
	private long _index;

	private long flags;
	private long instanceStart;
	private long instanceSize;
	private long reserved;
	private String name;
	private ObjectiveC2_MethodList baseMethods;
	private ObjectiveC2_ProtocolList baseProtocols;
	private ObjectiveC2_InstanceVariableList ivars;
	private long weakIvarLayout;
	private ObjectiveC2_PropertyList baseProperties;

	public ObjectiveC2_ClassRW() {
	}

	public ObjectiveC2_ClassRW(ObjectiveC2_State state, BinaryReader reader) throws IOException {
		this._state = state;
		this._index = reader.getPointerIndex();

		if (state.is32bit) {
			flags         = reader.readNextInt() & Conv.INT_MASK;
			instanceStart = reader.readNextInt() & Conv.INT_MASK;
			instanceSize  = reader.readNextInt() & Conv.INT_MASK;
			reserved      = reader.readNextInt() & Conv.INT_MASK;
		}
		else {
			flags         = reader.readNextLong();
			instanceStart = reader.readNextLong();
			instanceSize  = reader.readNextLong();
		}

		readName(reader);
		readBaseMethods(reader);
		readBaseProtocols(reader);
		readInstanceVariables(reader);

		weakIvarLayout = ObjectiveC1_Utilities.readNextIndex(reader, state.is32bit);

		readBaseProperties(reader);
	}

	public long getIndex() {
		return _index;
	}

	public String getName() {
		return name;
	}

	public long getFlags() {
		return flags;
	}
	public long getInstanceStart() {
		return instanceStart;
	}
	public long getInstanceSize() {
		return instanceSize;
	}
	public long getReserved() {
		return reserved;
	}
	public long getWeakIvarLayout() {
		return weakIvarLayout;
	}

	public ObjectiveC2_MethodList getBaseMethods() {
		return baseMethods;
	}

	public ObjectiveC2_ProtocolList getBaseProtocols() {
		return baseProtocols;
	}

	public ObjectiveC2_InstanceVariableList getInstanceVariables() {
		return ivars;
	}

	public ObjectiveC2_PropertyList getBaseProperties() {
		return baseProperties;
	}

	private void readName(BinaryReader reader) throws IOException {
		long nameIndex = ObjectiveC1_Utilities.readNextIndex(reader, _state.is32bit);
		if (nameIndex != 0) {
			name = reader.readAsciiString( nameIndex );
		}
	}

	private void readBaseProperties(BinaryReader reader) throws IOException {
		long propertiesIndex = ObjectiveC1_Utilities.readNextIndex(reader, _state.is32bit);
		if (propertiesIndex != 0) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(propertiesIndex);
			baseProperties = new ObjectiveC2_PropertyList( _state, reader );
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readInstanceVariables(BinaryReader reader)
			throws IOException {
		long instanceVariablesIndex = ObjectiveC1_Utilities.readNextIndex(reader, _state.is32bit);
		if (instanceVariablesIndex != 0) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(instanceVariablesIndex);
			ivars = new ObjectiveC2_InstanceVariableList( _state, reader );
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readBaseProtocols(BinaryReader reader) throws IOException {
		long protocolsIndex = ObjectiveC1_Utilities.readNextIndex(reader, _state.is32bit);
		if (protocolsIndex != 0) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(protocolsIndex);
			baseProtocols = new ObjectiveC2_ProtocolList(_state, reader);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readBaseMethods(BinaryReader reader) throws IOException {
		long methodsIndex = ObjectiveC1_Utilities.readNextIndex(reader, _state.is32bit);
		if (methodsIndex != 0) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(methodsIndex);
			baseMethods = new ObjectiveC2_MethodList( _state, reader, ObjectiveC_MethodType.INSTANCE );
			reader.setPointerIndex(originalIndex);
		}
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(NAME, 0);

		if (_state.is32bit) {
			struct.add(DWORD, "flags", null);
			struct.add(DWORD, "instanceStart", null);
			struct.add(DWORD, "instanceSize", null);
			struct.add(DWORD, "reserved", null);
		}
		else {
			struct.add(QWORD, "flags", null);
			struct.add(QWORD, "instanceStart", null);
			struct.add(QWORD, "instanceSize", null);
		}

		struct.add(new PointerDataType(ASCII),                                                _state.pointerSize, "name", null);
		struct.add(new PointerDataType(ObjectiveC2_MethodList.toGenericDataType()),           _state.pointerSize, "baseMethods", null);
		struct.add(new PointerDataType(ObjectiveC2_ProtocolList.toGenericDataType(_state)),   _state.pointerSize, "baseProtocols", null);
		struct.add(new PointerDataType(ObjectiveC2_InstanceVariableList.toGenericDataType()), _state.pointerSize, "ivars", null);

		if (_state.is32bit) {
			struct.add(DWORD, "weakIvarLayout", null);
		}
		else {
			struct.add(QWORD, "weakIvarLayout", null);
		}

		struct.add(new PointerDataType(ObjectiveC2_PropertyList.toGenericDataType()), _state.pointerSize, "baseProperties", null);

		struct.setCategoryPath(ObjectiveC2_Constants.CATEGORY_PATH);
		return struct;
	}

	public void applyTo() throws Exception {
		Address address = ObjectiveC1_Utilities.toAddress(_state.program, getIndex());

		try {
			ObjectiveC1_Utilities.applyData(_state.program, toDataType(), address);
		}
		catch (Exception e) {}

		try {
			Namespace namespace = ObjectiveC1_Utilities.createNamespace(_state.program, ObjectiveC1_Constants.NAMESPACE, ObjectiveC2_ClassRW.NAME);
			ObjectiveC1_Utilities.createSymbol(_state.program, namespace, getName(), address);
		}
		catch (Exception e) {}

		Namespace namespace = ObjectiveC1_Utilities.getClassNamespace(_state.program, null, getName());

		if (baseMethods != null) {
			baseMethods.applyTo(namespace);
		}
		if (baseProtocols != null) {
			baseProtocols.applyTo(namespace);
		}
		if (ivars != null) {
			ivars.applyTo(namespace);
		}
		if (baseProperties != null) {
			baseProperties.applyTo(namespace);
		}
	}
}
