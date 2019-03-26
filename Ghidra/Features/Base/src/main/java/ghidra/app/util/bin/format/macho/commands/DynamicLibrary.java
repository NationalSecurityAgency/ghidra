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
 * Represents a dylib structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
 */
public class DynamicLibrary implements StructConverter {
	private LoadCommandString name;
	private int timestamp;
	private int current_version;
	private int compatibility_version;

	public static DynamicLibrary createDynamicLibrary(FactoryBundledWithBinaryReader reader,
			LoadCommand command) throws IOException {
		DynamicLibrary dynamicLibrary =
			(DynamicLibrary) reader.getFactory().create(DynamicLibrary.class);
		dynamicLibrary.initDynamicLibrary(reader, command);
		return dynamicLibrary;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public DynamicLibrary() {
	}

	private void initDynamicLibrary(FactoryBundledWithBinaryReader reader, LoadCommand command)
			throws IOException {
		name = LoadCommandString.createLoadCommandString(reader, command);
		timestamp = reader.readNextInt();
		current_version = reader.readNextInt();
		compatibility_version = reader.readNextInt();
	}

	public LoadCommandString getName() {
		return name;
	}

	public int getTimestamp() {
		return timestamp;
	}

	public int getCurrentVersion() {
		return current_version;
	}

	public int getCompatibilityVersion() {
		return compatibility_version;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dylib", 0);
		struct.add(name.toDataType(), "name", null);
		struct.add(DWORD, "timestamp", null);
		struct.add(DWORD, "current_version", null);
		struct.add(DWORD, "compatibility_version", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	@Override
	public String toString() {
		return name.toString();
	}

}
