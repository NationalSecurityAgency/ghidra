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
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents an lc_str union.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
 */
public class LoadCommandString implements StructConverter {
	private int offset;
	private String string;

	static LoadCommandString createLoadCommandString(FactoryBundledWithBinaryReader reader,
			LoadCommand command) throws IOException {
		LoadCommandString loadCommandString =
			(LoadCommandString) reader.getFactory().create(LoadCommandString.class);
		loadCommandString.initLoadCommandString(reader, command);
		return loadCommandString;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY
	 * METHODS INSTEAD.
	 */
	public LoadCommandString() {
	}

	private void initLoadCommandString(FactoryBundledWithBinaryReader reader, LoadCommand command)
			throws IOException {
		offset = reader.readNextInt();
		string = reader.readAsciiString(command.getStartIndex() + offset);
	}

	public String getString() {
		return string;
	}

	public int getOffset() {
		return offset;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("lc_str", 0);
		struct.add(DWORD, "offset", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	@Override
	public String toString() {
		return string;
	}

}
