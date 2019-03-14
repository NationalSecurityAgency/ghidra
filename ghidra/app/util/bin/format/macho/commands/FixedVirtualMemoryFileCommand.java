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

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
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
 * Represents a fvmfile_command structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
 */
public class FixedVirtualMemoryFileCommand extends LoadCommand {
	private LoadCommandString name;
	private int header_addr;

	public static FixedVirtualMemoryFileCommand createFixedVirtualMemoryFileCommand(
			FactoryBundledWithBinaryReader reader) throws IOException {
		FixedVirtualMemoryFileCommand command =
			(FixedVirtualMemoryFileCommand) reader.getFactory().create(
				FixedVirtualMemoryFileCommand.class);
		command.initFixedVirtualMemoryFileCommand(reader);
		return command;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public FixedVirtualMemoryFileCommand() {
	}

	private void initFixedVirtualMemoryFileCommand(FactoryBundledWithBinaryReader reader)
			throws IOException {
		initLoadCommand(reader);
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
	public int getHeaderAddress() {
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
	public void markup(MachHeader header, FlatProgramAPI api, Address baseAddress, boolean isBinary,
			ProgramModule parentModule, TaskMonitor monitor, MessageLog log) {
		updateMonitor(monitor);
		if (isBinary) {
			try {
				createFragment(api, baseAddress, parentModule);
			}
			catch (Exception e) {
				log.appendException(e);
			}
			Address addr = baseAddress.getNewAddress(getStartIndex());
			try {
				api.createData(addr, toDataType());
			}
			catch (Exception e) {
				log.appendMsg("Unable to create " + getCommandName() + " - " + e.getMessage());
			}
			try {
				int strLen = getCommandSize() - name.getOffset();
				Address strAddr = addr.add(name.getOffset());
				api.createAsciiString(strAddr, strLen);
			}
			catch (Exception e) {
				log.appendMsg("Unable to create load command string for " + getCommandName() +
					" - " + e.getMessage());
			}
		}
	}
}
