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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class ObjectiveC2_Cache implements StructConverter {
	private ObjectiveC2_State _state;

	private long cache;

	public ObjectiveC2_Cache(ObjectiveC2_State state, BinaryReader reader) throws IOException {
		this._state = state;

		if (state.is32bit) {
			cache = reader.readNextInt() & 0xffffffffL;
		}
		else {
			cache = reader.readNextLong();
		}
	}

	public long getCache() {
		return cache;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		if (_state.is32bit) {
			return new TypedefDataType("Cache", DWORD);
		}
		return new TypedefDataType("Cache", QWORD);
	}

	public void applyTo() throws Exception {
	}
}
