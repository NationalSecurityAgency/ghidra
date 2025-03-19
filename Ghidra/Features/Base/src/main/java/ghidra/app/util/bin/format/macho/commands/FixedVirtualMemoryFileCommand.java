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
package ghidra.app.util.bin.format.macho.commands;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.ProgramModule;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a fvmfile_command structure 
 */
public class FixedVirtualMemoryFileCommand extends LoadCommand {
	private LoadCommandString name;
	private long header_addr;

	public FixedVirtualMemoryFileCommand(BinaryReader reader) throws IOException {
		super(reader);
	}

	/**
	 * Returns the file's pathname.
	 * @return the file's pathname
	 */
	public String getPathname() {
		return name.getString();
	}

	/**
	 * Returns the file's virtual address.
	 * @return the file's virtual address
	 */
	public long getHeaderAddress() {
		return header_addr;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getCommandName(), 0);
		struct.add(DWORD, "cmd", null);
		struct.add(DWORD, "cmdsize", null);
		struct.add(name.toDataType(), "name", null);
		struct.add(DWORD, "header_addr", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	@Override
	public String getCommandName() {
		return "fvmfile_command";
	}

	@Override
	public void markupRawBinary(MachHeader header, FlatProgramAPI api, Address baseAddress,
			ProgramModule parentModule, TaskMonitor monitor, MessageLog log) {
		try {
			super.markupRawBinary(header, api, baseAddress, parentModule, monitor, log);

			Address addr = baseAddress.getNewAddress(getStartIndex());
			int strLen = getCommandSize() - name.getOffset();
			Address strAddr = addr.add(name.getOffset());
			api.createAsciiString(strAddr, strLen);
		}
		catch (Exception e) {
			log.appendMsg("Unable to create " + getCommandName());

		}
	}
}
