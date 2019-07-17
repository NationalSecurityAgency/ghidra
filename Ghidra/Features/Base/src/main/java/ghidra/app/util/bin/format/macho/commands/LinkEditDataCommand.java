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
 * Represents a linkedit_data_command structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
 */
public class LinkEditDataCommand extends LoadCommand {
	private int dataoff;
	private int datasize;

	static LinkEditDataCommand createLinkEditDataCommand(FactoryBundledWithBinaryReader reader)
			throws IOException {
		LinkEditDataCommand command =
			(LinkEditDataCommand) reader.getFactory().create(LinkEditDataCommand.class);
		command.initLinkEditDataCommand(reader);
		return command;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public LinkEditDataCommand() {
	}

	private void initLinkEditDataCommand(FactoryBundledWithBinaryReader reader) throws IOException {
		initLoadCommand(reader);
		dataoff = reader.readNextInt();
		datasize = reader.readNextInt();
	}

	public int getDataOffset() {
		return dataoff;
	}

	public int getDataSize() {
		return datasize;
	}

	@Override
	public String getCommandName() {
		return "linkedit_data_command";
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
				api.setPlateComment(address,
					LoadCommandTypes.getLoadCommentTypeName(getCommandType()));

//TODO markup actual data

				if (datasize > 0) {
					Address start = baseAddress.getNewAddress(dataoff);
					api.createFragment(parentModule, getCommandName() + "_DATA", start, datasize);
				}
			}
		}
		catch (Exception e) {
			log.appendMsg("Unable to create " + getCommandName());
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getCommandName(), 0);
		struct.add(DWORD, "cmd", null);
		struct.add(DWORD, "cmdsize", null);
		struct.add(DWORD, "dataoff", null);
		struct.add(DWORD, "datasize", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

}
