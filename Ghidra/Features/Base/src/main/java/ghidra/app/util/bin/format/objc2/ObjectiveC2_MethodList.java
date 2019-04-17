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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.objectiveC.ObjectiveC_MethodList;
import ghidra.app.util.bin.format.objectiveC.ObjectiveC_MethodType;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class ObjectiveC2_MethodList extends ObjectiveC_MethodList {
	public final static String NAME = "method_list_t";

	private int entsize;
	private int count;

	public ObjectiveC2_MethodList(ObjectiveC2_State state, BinaryReader reader, ObjectiveC_MethodType methodType) throws IOException {
		super(state, reader, NAME);

		if (_index == 0) {
			return;
		}

		entsize = reader.readNextInt();
		count   = reader.readNextInt();

		for (int i = 0 ; i < count ; ++i) {
			methods.add( new ObjectiveC2_Method(state, reader, methodType) );
		}
	}

	public long getEntsize() {
		return entsize;
	}

	public long getCount() {
		return count;
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

		for (int i = 0 ; i < methods.size() ; ++i) {
			struct.add(methods.get(i).toDataType(), "method"+i, null);
		}

		struct.setCategoryPath(ObjectiveC2_Constants.CATEGORY_PATH);
		return struct;
	}

}
