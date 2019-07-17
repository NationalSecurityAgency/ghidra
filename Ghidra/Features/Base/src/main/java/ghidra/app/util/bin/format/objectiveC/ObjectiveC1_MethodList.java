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

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class ObjectiveC1_MethodList extends ObjectiveC_MethodList {
	public static final String NAME = "objc_method_list";

	private ObjectiveC1_MethodList obsolete;
	private int method_count;

	ObjectiveC1_MethodList(ObjectiveC1_State state, BinaryReader reader, ObjectiveC_MethodType methodType) throws IOException {
		super(state, reader, NAME);

		if (_index == 0) {
			return;
		}

		obsolete = new ObjectiveC1_MethodList(state, reader.clone(reader.readNextInt()), methodType );

		method_count = reader.readNextInt();

		for (int i = 0 ; i < method_count ; ++i) {
			methods.add(new ObjectiveC1_Method(state, reader, methodType));
		}
	}

	public ObjectiveC1_MethodList getObsolete() {
		return obsolete;
	}

	public int getMethodCount() {
		return method_count;
	}

	public static DataType toGenericDataType(ObjectiveC1_State state)
			throws DuplicateNameException {
		Structure struct = new StructureDataType(NAME, 0);
		struct.setCategoryPath(ObjectiveC1_Constants.CATEGORY_PATH);
		struct.add(PointerDataType.getPointer(struct, state.pointerSize), "obsolete", null);
		struct.add(DWORD, "method_count", null);
		return struct;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(NAME+"_"+method_count+"_", 0);
		struct.setCategoryPath(ObjectiveC1_Constants.CATEGORY_PATH);
		if (obsolete == null) {
			struct.add(PointerDataType.getPointer(VOID, _state.pointerSize), "obsolete", null);
		}
		else {
			DataType obsoleteDT = obsolete.toDataType();
			struct.add(PointerDataType.getPointer(obsoleteDT, _state.pointerSize), "obsolete", null);
		}
		struct.add(DWORD, "method_count", null);
		if (method_count > 0) {
			DataType dt = methods.get(0).toDataType();
			struct.add(new ArrayDataType(dt, method_count, dt.getLength()), "method_list", null);
		}
		return struct;
	}



}
