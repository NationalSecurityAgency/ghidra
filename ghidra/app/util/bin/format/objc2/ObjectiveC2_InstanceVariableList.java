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
import ghidra.util.exception.DuplicateNameException;

public class ObjectiveC2_InstanceVariableList implements StructConverter {
	public final static String NAME = "ivar_list_t";

	private ObjectiveC2_State _state;
	private long _index;

	private int entsize;
	private int count;
	private List<ObjectiveC2_InstanceVariable> ivars = new ArrayList<ObjectiveC2_InstanceVariable>();

	public ObjectiveC2_InstanceVariableList(ObjectiveC2_State state, BinaryReader reader) throws IOException {
		this._state = state;
		this._index = reader.getPointerIndex();

		entsize = reader.readNextInt();
		count   = reader.readNextInt();

		for (int i = 0 ; i < count ; ++i) {
			ivars.add( new ObjectiveC2_InstanceVariable(state, reader) );
		}
	}

	public long getEntsize() {
		return entsize;
	}

	public long getCount() {
		return count;
	}

	public List<ObjectiveC2_InstanceVariable> getIvars() {
		return ivars;
	}

	public long getIndex() {
		return _index;
	}

	public static DataType toGenericDataType() throws DuplicateNameException {
		Structure struct = new StructureDataType(NAME, 0);
		struct.add(DWORD, "entsize", null);
		struct.add(DWORD,   "count", null);
		struct.setCategoryPath(ObjectiveC2_Constants.CATEGORY_PATH);
		return struct;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(NAME+'_'+count+'_', 0);

		struct.add(DWORD, "entsize", null);
		struct.add(DWORD,   "count", null);

		for (int i = 0 ; i < ivars.size() ; ++i) {
			struct.add(ivars.get(i).toDataType(), "var"+i, null);
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
			Namespace instanceVariableNamespace = ObjectiveC1_Utilities.createNamespace(_state.program, ObjectiveC1_Constants.NAMESPACE, ObjectiveC2_InstanceVariableList.NAME);
			ObjectiveC1_Utilities.createSymbol(_state.program, instanceVariableNamespace, namespace.getName(), address);
		}
		catch (Exception e) {}

		for (ObjectiveC2_InstanceVariable ivar : getIvars()) {
			ivar.applyTo(namespace);
		}
	}
}
