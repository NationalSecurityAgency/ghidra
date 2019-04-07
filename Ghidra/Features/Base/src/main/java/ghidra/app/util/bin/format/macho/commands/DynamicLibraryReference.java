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
 * Represents a dylib_reference structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
 */
public class DynamicLibraryReference implements StructConverter {
	private int isym;
	private int flags;

	static DynamicLibraryReference createDynamicLibraryReference(
			FactoryBundledWithBinaryReader reader) throws IOException {
		DynamicLibraryReference dynamicLibraryReference =
			(DynamicLibraryReference) reader.getFactory().create(DynamicLibraryReference.class);
		dynamicLibraryReference.initDynamicLibraryReference(reader);
		return dynamicLibraryReference;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public DynamicLibraryReference() {
	}

	private void initDynamicLibraryReference(FactoryBundledWithBinaryReader reader)
			throws IOException {
		int value = reader.readNextInt();

		if (reader.isLittleEndian()) {
			isym = (value & 0x00ffffff);
			flags = (value & 0xff000000) >> 24;
		}
		else {
			isym = (value & 0xffffff00) >> 8;
			flags = (value & 0x000000ff);
		}
	}

	public int getSymbolIndex() {
		return isym;
	}

	public int getFlags() {
		return flags;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dylib_reference", 0);
		struct.add(DWORD, "isym_flags", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
