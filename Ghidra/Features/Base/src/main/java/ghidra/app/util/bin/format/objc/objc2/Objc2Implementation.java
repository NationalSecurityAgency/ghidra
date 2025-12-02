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
package ghidra.app.util.bin.format.objc.objc2;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.objc.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class Objc2Implementation extends ObjcTypeMetadataStructure {
	private boolean _isSmall = false;

	private long imp;

	public Objc2Implementation(Program program, ObjcState state, BinaryReader reader,
			boolean isSmall) throws IOException {
		super(program, state, reader.getPointerIndex());
		this._isSmall = isSmall;

		imp = isSmall ? base + reader.readNextInt() : ObjcUtils.readNextIndex(reader, is32bit);
	}

	public Objc2Implementation(Program program, ObjcState state, BinaryReader reader)
			throws IOException {
		this(program, state, reader, false);
	}

	public long getImplementation() {
		return imp;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		if (_isSmall) {
			return new TypedefDataType("ImplementationOffset", DWORD);
		}
		else if (is32bit) {
			return new TypedefDataType("Implementation", DWORD);
		}
		return new TypedefDataType("Implementation", QWORD);
	}

	@Override
	public void applyTo(Namespace namespace, TaskMonitor monitor) throws Exception {
		// do nothing
	}

}
