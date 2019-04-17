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

public class ExceptionStateX86_64 implements StructConverter {
	public int trapno;
	public int err;
	public long faultvaddr;

	ExceptionStateX86_64(BinaryReader reader) throws IOException {
		trapno = reader.readNextInt();
		err = reader.readNextInt();
		faultvaddr = reader.readNextLong();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("x86_exception_state64", 0);
		struct.add(DWORD, "trapno", null);
		struct.add(DWORD, "err", null);
		struct.add(QWORD, "faultvaddr", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
