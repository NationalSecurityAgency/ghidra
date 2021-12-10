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
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.util.Conv;
import ghidra.util.exception.DuplicateNameException;

public class ObjectiveC2_Implementation implements StructConverter {
	private boolean _is32bit;
	private long _index;
	private boolean _isSmall = false;

	private long imp;

	public ObjectiveC2_Implementation(ObjectiveC2_State state, BinaryReader reader, boolean isSmall)
			throws IOException {
		this._is32bit = state.is32bit;
		this._index = reader.getPointerIndex();
		this._isSmall = isSmall;

		if (isSmall) {
			imp = _index + reader.readNextInt();
		}
		else {
			if (state.is32bit) {
				imp = reader.readNextInt() & Conv.INT_MASK;
			}
			else {
				imp = reader.readNextLong();
			}
		}
	}

	public ObjectiveC2_Implementation(ObjectiveC2_State state, BinaryReader reader)
			throws IOException {
		this(state, reader, false);
	}

	public long getImplementation() {
		return imp;
	}

	public long getIndex() {
		return _index;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		if (_isSmall) {
			return new TypedefDataType("ImplementationOffset", DWORD);
		}
		else if (_is32bit) {
			return new TypedefDataType("Implementation", DWORD);
		}
		return new TypedefDataType("Implementation", QWORD);
	}

	public void applyTo() throws Exception {
	}

}
