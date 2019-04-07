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
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class ObjectiveC2_Category implements StructConverter {
	public final static String NAME = "category_t";

	private ObjectiveC2_State _state;
	private long _index;

	private String name;
	private ObjectiveC2_Class cls;
	private ObjectiveC2_MethodList instanceMethods;
	private ObjectiveC2_MethodList classMethods;
	private ObjectiveC2_ProtocolList protocols;
	private ObjectiveC2_PropertyList instanceProperties;

	public ObjectiveC2_Category(ObjectiveC2_State state, BinaryReader reader) throws IOException {
		this._state = state;
		this._index = reader.getPointerIndex();

		readName(reader);
		readClass(reader);
		readInstanceMethods(reader);
		readClassMethods(reader);
		readProtocols(reader);
		readInstanceProperties(reader);
	}

	public long getIndex() {
		return _index;
	}

	public String getName() {
		return name;
	}

	public ObjectiveC2_Class getCls() {
		return cls;
	}

	public ObjectiveC2_MethodList getInstanceMethods() {
		return instanceMethods;
	}

	public ObjectiveC2_MethodList getClassMethods() {
		return classMethods;
	}

	public ObjectiveC2_ProtocolList getProtocols() {
		return protocols;
	}

	public ObjectiveC2_PropertyList getInstanceProperties() {
		return instanceProperties;
	}

	private void readName(BinaryReader reader) throws IOException {
		long index = ObjectiveC1_Utilities.readNextIndex(reader, _state.is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			name = reader.readAsciiString(index);
		}
	}

	private void readClass(BinaryReader reader) throws IOException {
		long index = ObjectiveC1_Utilities.readNextIndex(reader, _state.is32bit);

		if (_state.classIndexMap.containsKey(index)) {
			cls = _state.classIndexMap.get(index);
			return;
		}

		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			cls = new ObjectiveC2_Class(_state, reader);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readInstanceMethods(BinaryReader reader) throws IOException {
		long index = ObjectiveC1_Utilities.readNextIndex(reader, _state.is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			instanceMethods = new ObjectiveC2_MethodList(_state, reader, ObjectiveC_MethodType.INSTANCE);
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

	private void readProtocols(BinaryReader reader) throws IOException {
		long index = ObjectiveC1_Utilities.readNextIndex(reader, _state.is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			protocols = new ObjectiveC2_ProtocolList(_state, reader);
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
		StringBuffer buffer = new StringBuffer();
		buffer.append(NAME);

		if (cls == null) {
			buffer.append("<no_class>");
		}

		Structure struct = new StructureDataType(buffer.toString(), 0);

		struct.add(new PointerDataType(STRING), _state.pointerSize, "name", null);

		if (cls == null) {
			struct.add(new PointerDataType(VOID), _state.pointerSize, "cls", null);
		}
		else {
			struct.add(new PointerDataType(cls.toDataType()), _state.pointerSize, "cls", null);
		}

		struct.add(new PointerDataType(ObjectiveC2_MethodList.toGenericDataType()),         _state.pointerSize, "instanceMethods", null);
		struct.add(new PointerDataType(ObjectiveC2_MethodList.toGenericDataType()),         _state.pointerSize, "classMethods", null);
		struct.add(new PointerDataType(ObjectiveC2_ProtocolList.toGenericDataType(_state)), _state.pointerSize, "protocols", null);
		struct.add(new PointerDataType(ObjectiveC2_PropertyList.toGenericDataType()),       _state.pointerSize, "instanceProperties", null);

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
			Namespace categoryNamespace = ObjectiveC1_Utilities.createNamespace(_state.program, ObjectiveC1_Constants.NAMESPACE, ObjectiveC2_Category.NAME);
			ObjectiveC1_Utilities.createSymbol(_state.program, categoryNamespace, getName(), address);
		}
		catch (Exception e) {}

		String string = null;
		try {
			string = cls.getData().getName()+'_'+name+'_';
		}
		catch (Exception e) {
			string = name;
		}
		Namespace namespace = ObjectiveC1_Utilities.createNamespace(_state.program, ObjectiveC1_Constants.NAMESPACE, "Categories", string);

		if (cls != null) {
			cls.applyTo();
		}
		if (instanceMethods != null) {
			instanceMethods.applyTo(namespace);
		}
		if (classMethods != null) {
			classMethods.applyTo(namespace);
		}
		if (protocols != null) {
			protocols.applyTo(namespace);
		}
		if (instanceProperties != null) {
			instanceProperties.applyTo(namespace);
		}
	}
}
