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
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a build_version_command structure 
 */
public class BuildVersionCommand extends LoadCommand {

	private int platform;
	private int minos;
	private int sdk;
	private long ntools;
	private BuildToolVersion[] buildToolVersions;

	BuildVersionCommand(BinaryReader reader) throws IOException {
		super(reader);

		platform = reader.readNextInt();
		minos = reader.readNextInt();
		sdk = reader.readNextInt();
		ntools = checkCount(reader.readNextUnsignedInt());
		buildToolVersions = new BuildToolVersion[(int) ntools];
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
			struct.add(new ArrayDataType(buildToolVersionDataType, (int) ntools,
				buildToolVersionDataType.getLength()), "build_tool_version[]", null);
		}
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	@Override
	public String getCommandName() {
		return "build_version_command";
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

	public long getNumTools() {
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
