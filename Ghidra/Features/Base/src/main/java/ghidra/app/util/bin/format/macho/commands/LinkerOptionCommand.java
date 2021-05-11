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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.ProgramModule;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a linker_option_command structure
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
 */
public class LinkerOptionCommand extends LoadCommand {

	private int count;
	private List<String> linkerOptions;

	static LinkerOptionCommand createLinkerOptionCommand(FactoryBundledWithBinaryReader reader)
			throws IOException {

		LinkerOptionCommand command =
			(LinkerOptionCommand) reader.getFactory().create(LinkerOptionCommand.class);
		command.initLinkerOptionCommand(reader);
		return command;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public LinkerOptionCommand() {
	}

	private void initLinkerOptionCommand(FactoryBundledWithBinaryReader reader) throws IOException {
		initLoadCommand(reader);
		count = reader.readNextInt();
		linkerOptions = new ArrayList<>(count);
		long readerIndex = reader.getPointerIndex();
		for (int i = 0; i < count; i++) {
			String str = reader.readTerminatedString(readerIndex, '\0');
			linkerOptions.add(str);
			readerIndex += str.length() + 1;
		}
	}
	
	/**
	 * Gets this {@link LinkerOptionCommand}'s linker options
	 * 
	 * @return This {@link LinkerOptionCommand}'s linker options 
	 */
	public List<String> getLinkerOptions() {
		return linkerOptions;
	}

	@Override
	public String getCommandName() {
		return "linker_option_command";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getCommandName(), 0);
		struct.add(DWORD, "cmd", null);
		struct.add(DWORD, "cmdsize", null);
		struct.add(DWORD, "count", null);
		return struct;
	}

	@Override
	public void markup(MachHeader header, FlatProgramAPI api, Address baseAddress, boolean isBinary,
			ProgramModule parentModule, TaskMonitor monitor, MessageLog log) {
		updateMonitor(monitor);

		try {
			if (isBinary) {
				createFragment(api, baseAddress, parentModule);
				Address address = baseAddress.getNewAddress(getStartIndex());
				api.createData(address, toDataType());
			}
		}
		catch (Exception e) {
			log.appendMsg("Unable to create " + getCommandName());
		}
	}

}
