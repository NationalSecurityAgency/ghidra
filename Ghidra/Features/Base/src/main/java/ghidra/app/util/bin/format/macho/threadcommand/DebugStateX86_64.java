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
package ghidra.app.util.bin.format.macho.threadcommand;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class DebugStateX86_64 implements StructConverter {
	public long dr0;
	public long dr1;
	public long dr2;
	public long dr3;
	public long dr4;
	public long dr5;
	public long dr6;
	public long dr7;

	DebugStateX86_64(BinaryReader reader) throws IOException {
		dr0 = reader.readNextLong();
		dr1 = reader.readNextLong();
		dr2 = reader.readNextLong();
		dr3 = reader.readNextLong();
		dr4 = reader.readNextLong();
		dr5 = reader.readNextLong();
		dr6 = reader.readNextLong();
		dr7 = reader.readNextLong();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("x86_debug_state64", 0);
		struct.add(QWORD, "dr0", null);
		struct.add(QWORD, "dr1", null);
		struct.add(QWORD, "dr2", null);
		struct.add(QWORD, "dr3", null);
		struct.add(QWORD, "dr4", null);
		struct.add(QWORD, "dr5", null);
		struct.add(QWORD, "dr6", null);
		struct.add(QWORD, "dr7", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
