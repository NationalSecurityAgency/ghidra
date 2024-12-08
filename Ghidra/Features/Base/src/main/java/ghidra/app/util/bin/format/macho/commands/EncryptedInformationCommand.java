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
 * Represents an encryption_info_command structure
 */
public class EncryptedInformationCommand extends LoadCommand {
	private int cryptoff;
	private int cryptsize;
	private int cryptid;
	
	private boolean is32bit;

	EncryptedInformationCommand(BinaryReader reader, boolean is32bit) throws IOException {
		super(reader);
		this.is32bit = is32bit;

		cryptoff = reader.readNextInt();
		cryptsize = reader.readNextInt();
		cryptid = reader.readNextInt();
	}

	public int getCryptID() {
		return cryptid;
	}

	public int getCryptOffset() {
		return cryptoff;
	}

	public int getCryptSize() {
		return cryptsize;
	}

	@Override
	public String getCommandName() {
		return "encryption_info_command";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getCommandName(), 0);
		struct.add(DWORD, "cmd", null);
		struct.add(DWORD, "cmdsize", null);
		struct.add(DWORD, "cryptoff", null);
		struct.add(DWORD, "cryptsize", null);
		struct.add(DWORD, "cryptid", null);
		if (!is32bit) {
			struct.add(DWORD, "pad", null);
		}
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

}
