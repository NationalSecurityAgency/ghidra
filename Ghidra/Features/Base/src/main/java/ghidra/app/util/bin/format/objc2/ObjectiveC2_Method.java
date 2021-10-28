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
import ghidra.app.util.bin.format.objectiveC.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class ObjectiveC2_Method extends ObjectiveC_Method {
	private String name;
	private String types;
	private ObjectiveC2_Implementation imp;

	private boolean isSmall;

	public ObjectiveC2_Method(ObjectiveC2_State state, BinaryReader reader,
			ObjectiveC_MethodType methodType, boolean isSmallList) throws IOException {
		super(state, reader, methodType);

		isSmall = isSmallList;

		if (isSmallList) {
			int nameOffset = (int)ObjectiveC1_Utilities.readNextIndex(reader, true);
			int namePtr = reader.readInt(_index + nameOffset);
			name = reader.readAsciiString(namePtr);

			int typesOffset = (int)ObjectiveC1_Utilities.readNextIndex(reader, true);
			types = reader.readAsciiString(_index + 4 + typesOffset);
		}
		else {
			long nameIndex = ObjectiveC1_Utilities.readNextIndex(reader, state.is32bit);
			name  = reader.readAsciiString(nameIndex);

			long typesIndex = ObjectiveC1_Utilities.readNextIndex(reader, state.is32bit);
			types = reader.readAsciiString(typesIndex);
		}
		
		imp = new ObjectiveC2_Implementation(state, reader, isSmallList);
	}

	@Override
	public String getName() {
		return name;
	}
	@Override
	public String getTypes() {
		return types;
	}
	@Override
	public long getImplementation() {
		return imp.getImplementation();
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType("method_t", 0);
		if (isSmall) {
			DataType sdw = SignedDWordDataType.dataType;
			String comment = "offset from this address";
			struct.add(sdw, sdw.getLength(), "name", comment);
			struct.add(sdw, sdw.getLength(), "types", comment);
			struct.add(sdw, sdw.getLength(), "imp", comment);
		}
		else {
			struct.add(new PointerDataType(STRING), _state.pointerSize, "name",  null);
			struct.add(new PointerDataType(STRING), _state.pointerSize, "types", null);
			struct.add(new PointerDataType(VOID),   _state.pointerSize, "imp",   null);
		}
		struct.setCategoryPath(ObjectiveC2_Constants.CATEGORY_PATH);
		return struct;
	}

}
