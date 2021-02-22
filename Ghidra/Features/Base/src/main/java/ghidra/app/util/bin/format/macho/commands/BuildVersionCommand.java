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

import ghidra.app.util.bin.StructConverter;
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
 * Represents a build_version_command structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
 */
public class BuildVersionCommand extends LoadCommand {

	private int platform;
	private int minos;
	private int sdk;
	private int ntools;
	private BuildToolVersion[] buildToolVersions;

	static BuildVersionCommand createBuildVersionCommand(FactoryBundledWithBinaryReader reader)
			throws IOException {

		BuildVersionCommand command =
			(BuildVersionCommand) reader.getFactory().create(BuildVersionCommand.class);
		command.initEntryPointCommand(reader);
		return command;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public BuildVersionCommand() {
	}

	private void initEntryPointCommand(FactoryBundledWithBinaryReader reader) throws IOException {
		initLoadCommand(reader);

		platform = reader.readNextInt();
		minos = reader.readNextInt();
		sdk = reader.readNextInt();
		ntools = reader.readNextInt();
		buildToolVersions = new BuildToolVersion[ntools];
		for (int i = 0; i < ntools; i++) {
			buildToolVersions[i] = new BuildToolVersion(reader.readNextInt(), reader.readNextInt());
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		DataType buildToolVersionDataType = new BuildToolVersion(0, 0).toDataType();
		StructureDataType struct = new StructureDataType(getCommandName(), 0);
		struct.add(DWORD, "cmd", null);
		struct.add(DWORD, "cmdsize", null);
		struct.add(DWORD, "platform", null);
		struct.add(DWORD, "minos", null);
		struct.add(DWORD, "sdk", null);
		struct.add(DWORD, "ntools", null);
		if (ntools > 0) {
			struct.add(new ArrayDataType(buildToolVersionDataType, ntools,
				buildToolVersionDataType.getLength()), "build_tool_version[]", null);
		}
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	@Override
	public String getCommandName() {
		return "build_version_command";
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

	public int getPlatform() {
		return platform;
	}

	public int getMinOS() {
		return minos;
	}

	public int getSdk() {
		return sdk;
	}

	public int getNumTools() {
		return ntools;
	}

	public static class BuildToolVersion implements StructConverter {

		private int tool;
		private int version;

		public BuildToolVersion(int tool, int version) {
			this.tool = tool;
			this.version = version;
		}

		public int getTool() {
			return tool;
		}

		public int getVersion() {
			return version;
		}

		@Override
		public DataType toDataType() throws DuplicateNameException, IOException {
			StructureDataType struct = new StructureDataType("build_tool_version", 0);
			struct.add(DWORD, "tool", null);
			struct.add(DWORD, "version", null);
			struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
			return struct;
		}
	}

}
