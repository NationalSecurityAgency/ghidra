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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.objectiveC.ObjectiveC1_Constants;
import ghidra.app.util.bin.format.objectiveC.ObjectiveC1_Utilities;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.Conv;
import ghidra.util.exception.DuplicateNameException;

public class ObjectiveC2_ProtocolList implements StructConverter {
	public final static String NAME = "protocol_list_t";

	private ObjectiveC2_State _state;
	private long _index;

	private List<ObjectiveC2_Protocol> protocols = new ArrayList<ObjectiveC2_Protocol>();

	public ObjectiveC2_ProtocolList(ObjectiveC2_State state, BinaryReader reader) throws IOException {
		this._state = state;
		this._index = reader.getPointerIndex();

		long count = state.is32bit ? reader.readNextInt() & Conv.INT_MASK : reader.readNextLong();

		for (long i = 0 ; i < count ; ++i) {
			long protocolIndex = ObjectiveC1_Utilities.readNextIndex(reader, state.is32bit);
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(protocolIndex);
			protocols.add( new ObjectiveC2_Protocol(state, reader) );
			reader.setPointerIndex(originalIndex);
		}
	}

	public long getCount() {
		return protocols.size();
	}

	public long getIndex() {
		return _index;
	}

	public List<ObjectiveC2_Protocol> getProtocols() {
		return protocols;
	}

	public static DataType toGenericDataType(ObjectiveC2_State state)
			throws DuplicateNameException {
		Structure struct = new StructureDataType(NAME, 0);
		if (state.is32bit) {
			struct.add(DWORD, "count", null);
		}
		else {
			struct.add(QWORD, "count", null);
		}
		struct.setCategoryPath(ObjectiveC2_Constants.CATEGORY_PATH);
		return struct;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(NAME+'_'+protocols.size()+'_', 0);

		if (_state.is32bit) {
			struct.add(DWORD, "count", null);
		}
		else {
			struct.add(QWORD, "count", null);
		}

		for (int i = 0 ; i < protocols.size() ; ++i) {
			DataType dataType = protocols.get(i).toDataType();
			struct.add(new PointerDataType(dataType), _state.pointerSize, "protocol"+i, null);
		}

		struct.setCategoryPath(ObjectiveC2_Constants.CATEGORY_PATH);
		return struct;
	}

	public void applyTo(Namespace namespace) throws Exception {
		Address address = ObjectiveC1_Utilities.toAddress(_state.program, getIndex());
		try {
			ObjectiveC1_Utilities.applyData(_state.program, toDataType(), address);
		}
		catch (Exception e) {}

		try {
			Namespace protocolListNamespace = ObjectiveC1_Utilities.createNamespace(_state.program, ObjectiveC1_Constants.NAMESPACE, ObjectiveC2_ProtocolList.NAME);
			ObjectiveC1_Utilities.createSymbol(_state.program, protocolListNamespace, namespace.getName(), address);
		}
		catch (Exception e) {}

		for (ObjectiveC2_Protocol protocol : getProtocols()) {
			protocol.applyTo(namespace);
		}
	}
}
