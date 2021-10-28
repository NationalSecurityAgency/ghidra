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
 * Represents a kext_command
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-7195.60.75/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
 */
public class FileSetEntryCommand extends LoadCommand {

	private long vmaddr;
	private long fileoff;
	private String entryName;
	private long unknown;

	boolean is32bit;

	public static FileSetEntryCommand createFileSetEntryCommand(
			FactoryBundledWithBinaryReader reader, boolean is32bit) throws IOException {
		FileSetEntryCommand filesetEntryCommand =
			(FileSetEntryCommand) reader.getFactory().create(FileSetEntryCommand.class);
		filesetEntryCommand.initFileSetEntryCommand(reader, is32bit);
		return filesetEntryCommand;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public FileSetEntryCommand() {
	}

	private void initFileSetEntryCommand(FactoryBundledWithBinaryReader reader, boolean is32bit)
			throws IOException {
		initLoadCommand(reader);
		this.is32bit = is32bit;

		if (is32bit) {
			vmaddr = reader.readNextUnsignedInt();
			fileoff = reader.readNextUnsignedInt();
			unknown = reader.readNextUnsignedInt();
		}
		else {
			vmaddr = reader.readNextLong();
			fileoff = reader.readNextLong();
			unknown = reader.readNextLong();
		}

		int stringSize = this.getCommandSize() - (8 + 3 * (is32bit ? 4 : 8));
		entryName = reader.readNextAsciiString(stringSize);
	}

	public String getFileSetEntryName() {
		return entryName;
	}

	public long getVMaddress() {
		return vmaddr;
	}

	public long getFileOffset() {
		return fileoff;
	}

	public long getUnknown() {
		return unknown;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getCommandName(), 0);
		struct.add(DWORD, "cmd", null);
		struct.add(DWORD, "cmdsize", null);

		if (is32bit) {
			struct.add(DWORD, "vmaddr", null);
			struct.add(DWORD, "fileoff", null);
			struct.add(DWORD, "unknown", null);
		}
		else {
			struct.add(QWORD, "vmaddr", null);
			struct.add(QWORD, "fileoff", null);
			struct.add(QWORD, "unknown", null);
		}
		int stringSize = getCommandSize() - (8 + 3 * (is32bit ? 4 : 8));
		struct.add(new StringDataType(), stringSize, "fileSetEntryname", null);

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
				api.setPlateComment(addr, getFileSetEntryName());
			}
		}
		catch (Exception e) {
			log.appendMsg("Unable to create " + getCommandName() + " - " + e.getMessage());
		}
	}

	@Override
	public String toString() {
		return getFileSetEntryName();
	}
}
