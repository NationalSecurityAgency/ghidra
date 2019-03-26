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
import ghidra.app.util.bin.format.objectiveC.ObjectiveC1_Utilities;
import ghidra.program.model.data.*;
import ghidra.util.Conv;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class ObjectiveC2_MessageReference implements StructConverter {
	public static final String NAME = "message_ref";

	public static int SIZEOF(ObjectiveC2_State state) {
		return 2 * state.pointerSize;
	}

	private ObjectiveC2_State _state;

	private long implementation;
	private String selector;

	public ObjectiveC2_MessageReference(ObjectiveC2_State state, BinaryReader reader) throws IOException {
		this._state = state;

		if (state.is32bit) {
			implementation = reader.readNextInt() & Conv.INT_MASK;
		}
		else {
			implementation = reader.readNextLong();
		}

		long selectorIndex = ObjectiveC1_Utilities.readNextIndex(reader, state.is32bit);
		if (selectorIndex != 0) {
			selector = reader.readAsciiString(selectorIndex);
		}
	}

	public long getImplementation() {
		return implementation;
	}

	public String getSelector() {
		return selector;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(NAME, 0);
		struct.add(new PointerDataType(VOID),  _state.pointerSize, "imp", null);
		struct.add(new PointerDataType(ASCII), _state.pointerSize, "sel", null);
		return struct;
	}
}

