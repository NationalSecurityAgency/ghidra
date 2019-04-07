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
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class ObjectiveC1_Category implements StructConverter {
	public static final long SIZEOF = 0;

	private ObjectiveC1_State _state;
	private long _index;

	private String category_name;
	private String class_name;
	private ObjectiveC1_MethodList instance_methods;
	private ObjectiveC1_MethodList class_methods;
	private ObjectiveC1_ProtocolList protocols;
	private int unknown0;
	private int unknown1;

	public ObjectiveC1_Category(ObjectiveC1_State state, BinaryReader reader) throws IOException {
		this._state = state;
		this._index = reader.getPointerIndex();

		category_name    = reader.readAsciiString( reader.readNextInt() );
		class_name       = reader.readAsciiString( reader.readNextInt() );
		instance_methods = new ObjectiveC1_MethodList(state, reader.clone(reader.readNextInt()), ObjectiveC_MethodType.INSTANCE);
		class_methods    = new ObjectiveC1_MethodList(state, reader.clone(reader.readNextInt()), ObjectiveC_MethodType.CLASS);
		protocols        = new ObjectiveC1_ProtocolList(state, reader.clone( reader.readNextInt() ));

		if (state.isARM) {
			unknown0     = reader.readNextInt();
			unknown1     = reader.readNextInt();
		}
	}

	public String getCategoryName() {
		return category_name;
	}

	public String getClassName() {
		return class_name;
	}

	public ObjectiveC1_MethodList getInstanceMethods() {
		return instance_methods;
	}

	public ObjectiveC1_MethodList getClassMethods() {
		return class_methods;
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
		String name = "objc_category";
		StructureDataType struct = new StructureDataType(name, 0);
		struct.setCategoryPath(ObjectiveC1_Constants.CATEGORY_PATH);
		struct.add(PointerDataType.getPointer(ASCII, _state.pointerSize), "category_name", null);
		struct.add(PointerDataType.getPointer(ASCII, _state.pointerSize), "class_name", null);
		struct.add(PointerDataType.getPointer(ObjectiveC1_MethodList.toGenericDataType(_state), _state.pointerSize), "instance_methods", null);
		struct.add(PointerDataType.getPointer(ObjectiveC1_MethodList.toGenericDataType(_state), _state.pointerSize), "class_methods", null);
		struct.add(PointerDataType.getPointer(ObjectiveC1_ProtocolList.toGenericDataType(_state), _state.pointerSize), "protocols", null);
		if (_state.isARM) {
			struct.add(DWORD, "unknown0", null);
			struct.add(DWORD, "unknown1", null);
		}
		return struct;
	}

	public void applyTo() throws Exception {
		if (_state.beenApplied.contains(_index)) {
			return;
		}
		_state.beenApplied.add(_index);

		Address address = _state.program.getAddressFactory().getDefaultAddressSpace().getAddress(_index);
		DataType dt = toDataType();
		_state.program.getListing().clearCodeUnits(address, address.add(dt.getLength()-1), false);
		_state.program.getListing().createData(address, dt);

		Namespace namespace = ObjectiveC1_Utilities.createNamespace(_state.program, ObjectiveC1_Constants.NAMESPACE, "Categories", class_name+'('+category_name+')');

		instance_methods.applyTo(namespace);
		class_methods.applyTo(namespace);
		protocols.applyTo();
	}
}
