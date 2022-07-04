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
 * Represents a fileset_entry_command
 */
public class FileSetEntryCommand extends LoadCommand {

	private long vmaddr;
	private long fileoff;
	private LoadCommandString entryId;
	private int reserved;

	/**
	 * Creates and parses a new {@link FileSetEntryCommand}
	 * 
	 * @param reader A {@link BinaryReader reader} that points to the start of the load command
	 * @throws IOException if an IO-related error occurs while parsing
	 */
	FileSetEntryCommand(BinaryReader reader) throws IOException {
		super(reader);
		vmaddr = reader.readNextLong();
		fileoff = reader.readNextLong();
		entryId = new LoadCommandString(reader, this);
		reserved = reader.readNextInt();
	}

	/**
	 * Gets the virtual address of the DYLIB
	 * 
	 * @return The virtual address of the DYLIB
	 */
	public long getVMaddress() {
		return vmaddr;
	}

	/**
	 * Gets the file offset of the DYLIB
	 * 
	 * @return the file offset of the DYLIB
	 */
	public long getFileOffset() {
		return fileoff;
	}

	/**
	 * Gets the identifier of the DYLIB
	 * 
	 * @return the identifier of the DYLIB
	 */
	public LoadCommandString getFileSetEntryId() {
		return entryId;
	}

	/**
	 * Gets the reserved field (should just be padding)
	 * 
	 * @return The reserved field
	 */
	public int getReserved() {
		return reserved;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getCommandName(), 0);
		struct.add(DWORD, "cmd", null);
		struct.add(DWORD, "cmdsize", null);
		struct.add(QWORD, "vmaddr", null);
		struct.add(QWORD, "fileoff", null);
		struct.add(entryId.toDataType(), "entry_id", null);
		struct.add(DWORD, "reserved", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	@Override
	public String getCommandName() {
		return "fileset_entry_command";
	}

	@Override
	public void markup(MachHeader header, FlatProgramAPI api, Address baseAddress, boolean isBinary,
			ProgramModule parentModule, TaskMonitor monitor, MessageLog log) {
		updateMonitor(monitor);
		try {
			if (isBinary) {
				createFragment(api, baseAddress, parentModule);
				Address addr = baseAddress.getNewAddress(getStartIndex());
				DataType fileSetEntryDT = toDataType();
				api.createData(addr, fileSetEntryDT);
				api.setPlateComment(addr, entryId.getString());
			}
		}
		catch (Exception e) {
			log.appendMsg("Unable to create " + getCommandName() + " - " + e.getMessage());
		}
	}

	@Override
	public String toString() {
		return entryId.getString();
	}
}
