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
package ghidra.app.util.bin.format.pe;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class DefaultDataDirectory extends DataDirectory implements StructConverter {

	DefaultDataDirectory(NTHeader ntHeader, BinaryReader reader) throws IOException {
		processDataDirectory(ntHeader, reader);
    }

	@Override
	public String getDirectoryName() {
		return TITLE;
	}

	@Override
	public boolean parse() throws IOException {
		//do nothing
		return true;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader nt) {
		//do nothing
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType ddstruct = new StructureDataType(DataDirectory.TITLE, 0);
		ddstruct.add(DWORD, "VirtualAddress", null);
		ddstruct.add(DWORD, "Size", null);
		ddstruct.setCategoryPath(new CategoryPath("/PE"));
		return ddstruct;
	}
}
