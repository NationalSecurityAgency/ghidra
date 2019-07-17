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
 * Represents a prebound_dylib_command structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
 */
public class PreboundDynamicLibraryCommand extends LoadCommand {
	private LoadCommandString name;
	private int nmodules;
	private LoadCommandString linkedModules;

	static PreboundDynamicLibraryCommand createPreboundDynamicLibraryCommand(
			FactoryBundledWithBinaryReader reader) throws IOException {
		PreboundDynamicLibraryCommand command =
			(PreboundDynamicLibraryCommand) reader.getFactory().create(
				PreboundDynamicLibraryCommand.class);
		command.initPreboundDynamicLibraryCommand(reader);
		return command;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public PreboundDynamicLibraryCommand() {
	}

	private void initPreboundDynamicLibraryCommand(FactoryBundledWithBinaryReader reader)
			throws IOException {
		initLoadCommand(reader);
		name = LoadCommandString.createLoadCommandString(reader, this);
		nmodules = reader.readNextInt();
		linkedModules = LoadCommandString.createLoadCommandString(reader, this);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getCommandName(), 0);
		struct.add(DWORD, "cmd", null);
		struct.add(DWORD, "cmdsize", null);
		struct.add(name.toDataType(), "name", null);
		struct.add(DWORD, "nmodules", null);
		struct.add(linkedModules.toDataType(), "linked_modules", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	/**
	 * Returns library's path name.
	 * @return library's path name
	 */
	public String getLibraryName() {
		return name.getString();
	}

	/**
	 * Returns number of modules in library.
	 * @return number of modules in library
	 */
	public int getNumberOfModules() {
		return nmodules;
	}

	/**
	 * Returns bit vector of linked modules.
	 * @return bit vector of linked modules
	 */
	public String getLinkedModules() {
		return linkedModules.getString();
	}

	@Override
	public String getCommandName() {
		return "prebound_dylib_command";
	}

	@Override
	public void markup(MachHeader header, FlatProgramAPI api, Address baseAddress, boolean isBinary,
			ProgramModule parentModule, TaskMonitor monitor, MessageLog log) {
		updateMonitor(monitor);
		try {
			if (isBinary) {
				createFragment(api, baseAddress, parentModule);
				Address addr = baseAddress.getNewAddress(getStartIndex());
				api.createData(addr, toDataType());

				int nameLen = getCommandSize() - name.getOffset();
				Address nameAddr = addr.add(name.getOffset());
				api.createAsciiString(nameAddr, nameLen);
			}
		}
		catch (Exception e) {
			log.appendMsg("Unable to create " + getCommandName() + " - " + e.getMessage());
		}
	}
}
