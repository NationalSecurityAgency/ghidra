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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class ObjectiveC1_InstanceVariableList implements StructConverter {
	public static final String NAME = "objc_method_list";

	private ObjectiveC1_State _state;
	private long _index;

	private int ivar_count;
	private List<ObjectiveC1_InstanceVariable> ivar_list = new ArrayList<ObjectiveC1_InstanceVariable>();

	ObjectiveC1_InstanceVariableList(ObjectiveC1_State state, BinaryReader reader) throws IOException {
		this._state = state;
		this._index = reader.getPointerIndex();
		if (_index == 0) {
			return;
		}

		ivar_count = reader.readNextInt();

		for (int i = 0 ; i < ivar_count ; ++i) {
			ivar_list.add(new ObjectiveC1_InstanceVariable(state, reader));
		}
	}

	public int getInstanceVariableCount() {
		return ivar_count;
	}

	public List<ObjectiveC1_InstanceVariable> getInstanceVariables() {
		return ivar_list;
	}

	public static DataType toGenericDataType() throws DuplicateNameException {
		Structure struct = new StructureDataType(NAME, 0);
		struct.setCategoryPath(ObjectiveC1_Constants.CATEGORY_PATH);
		struct.add(DWORD, "ivar_count", null);
		return struct;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("objc_ivar_list"+"_"+ivar_count+"_", 0);
		struct.setCategoryPath(ObjectiveC1_Constants.CATEGORY_PATH);
		struct.add(DWORD, "ivar_count", null);
		if (ivar_count > 0) {
			DataType dt = ivar_list.get(0).toDataType();
			struct.add(new ArrayDataType(dt, ivar_count, dt.getLength()), "ivar_list", null);
		}
		return struct;
	}

	public void applyTo() throws Exception {
		if (_index == 0) {
			return;
		}
		if (_state.beenApplied.contains(_index)) {
			return;
		}
		_state.beenApplied.add(_index);

		Address address = _state.program.getAddressFactory().getDefaultAddressSpace().getAddress(_index);
		DataType dt = toDataType();
		_state.program.getListing().clearCodeUnits(address, address.add(dt.getLength()-1), false);
		_state.program.getListing().createData(address, dt);
	}
}
