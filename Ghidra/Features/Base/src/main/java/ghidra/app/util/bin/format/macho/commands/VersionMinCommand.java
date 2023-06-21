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
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a version_min_command structure 
 */
public class VersionMinCommand extends LoadCommand {

	private int version;
	private int sdk;

	VersionMinCommand(BinaryReader reader) throws IOException {
		super(reader);

		version = reader.readNextInt();
		sdk = reader.readNextInt();
	}

	@Override
	public String getCommandName() {
		return "version_min_command";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getCommandName(), 0);
		struct.add(DWORD, "cmd", null);
		struct.add(DWORD, "cmdsize", null);
		struct.add(DWORD, "version", null);
		struct.add(DWORD, "sdk", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	public int getVersion() {
		return version;
	}

	public int getSdk() {
		return sdk;
	}

}
