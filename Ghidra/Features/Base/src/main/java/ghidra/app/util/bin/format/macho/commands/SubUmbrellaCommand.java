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
 * Represents a sub_umbrella_command structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
 */
public class SubUmbrellaCommand extends LoadCommand {
	private LoadCommandString sub_umbrella;

	static SubUmbrellaCommand createSubUmbrellaCommand(FactoryBundledWithBinaryReader reader)
			throws IOException {
		SubUmbrellaCommand command =
			(SubUmbrellaCommand) reader.getFactory().create(SubUmbrellaCommand.class);
		command.initSubUmbrellaCommand(reader);
		return command;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public SubUmbrellaCommand() {
	}

	private void initSubUmbrellaCommand(FactoryBundledWithBinaryReader reader) throws IOException {
		initLoadCommand(reader);
		sub_umbrella = LoadCommandString.createLoadCommandString(reader, this);
	}

	public LoadCommandString getSubUmbrellaFrameworkName() {
		return sub_umbrella;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getCommandName(), 0);
		struct.add(DWORD, "cmd", null);
		struct.add(DWORD, "cmdsize", null);
		struct.add(sub_umbrella.toDataType(), "sub_umbrella", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	@Override
	public String getCommandName() {
		return "sub_umbrella_command";
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
				int strLen = getCommandSize() - sub_umbrella.getOffset();
				Address strAddr = addr.add(sub_umbrella.getOffset());
				api.createAsciiString(strAddr, strLen);
			}
			catch (Exception e) {
				log.appendMsg("Unable to create load command string " + getCommandName() + " - " +
					e.getMessage());
			}
		}
	}
}
