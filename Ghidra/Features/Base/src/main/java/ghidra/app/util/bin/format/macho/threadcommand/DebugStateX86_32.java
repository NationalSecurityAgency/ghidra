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

public class DebugStateX86_32 implements StructConverter {
	public int dr0;
	public int dr1;
	public int dr2;
	public int dr3;
	public int dr4;
	public int dr5;
	public int dr6;
	public int dr7;

	DebugStateX86_32(BinaryReader reader) throws IOException {
		dr0 = reader.readNextInt();
		dr1 = reader.readNextInt();
		dr2 = reader.readNextInt();
		dr3 = reader.readNextInt();
		dr4 = reader.readNextInt();
		dr5 = reader.readNextInt();
		dr6 = reader.readNextInt();
		dr7 = reader.readNextInt();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("x86_debug_state32", 0);
		struct.add(DWORD, "dr0", null);
		struct.add(DWORD, "dr1", null);
		struct.add(DWORD, "dr2", null);
		struct.add(DWORD, "dr3", null);
		struct.add(DWORD, "dr4", null);
		struct.add(DWORD, "dr5", null);
		struct.add(DWORD, "dr6", null);
		struct.add(DWORD, "dr7", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
