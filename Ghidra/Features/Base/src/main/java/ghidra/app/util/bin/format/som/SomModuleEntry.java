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
package ghidra.app.util.bin.format.som;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a SOM {@code module_entry} structure
 * 
 * @see <a href="https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf">The 32-bit PA-RISC Run-time Architecture Document</a> 
 */
public class SomModuleEntry implements StructConverter {

	/** The size in bytes of a {@link SomModuleEntry} */
	public static final int SIZE = 0x14;

	private int drelocs;
	private int imports;
	private int importCount;
	private int flags;
	private int reserved1;
	private int moduleDependencies;
	private int reserved2;

	/**
	 * Creates a new {@link SomModuleEntry}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the module list
	 * @throws IOException if there was an IO-related error
	 */
	public SomModuleEntry(BinaryReader reader) throws IOException {
		drelocs = reader.readNextInt();
		imports = reader.readNextInt();
		importCount = reader.readNextInt();
		flags = reader.readNextUnsignedByte();
		reserved1 = reader.readNextUnsignedByte();
		moduleDependencies = reader.readNextUnsignedShort();
		reserved2 = reader.readNextInt();
	}

	/**
	 * {@return the text address into the dynamic relocation table}
	 */
	public int getDrelocs() {
		return drelocs;
	}

	/**
	 * {@return the text address into the module import table}
	 */
	public int getImports() {
		return imports;
	}

	/**
	 * {@return the number of symbol entries in the module import table belonging to this module}
	 */
	public int getImportCount() {
		return importCount;
	}

	/**
	 * {@return the flags}
	 */
	public int getFlags() {
		return flags;
	}

	/**
	 * {@return the first reserved value}
	 */
	public int getReserved1() {
		return reserved1;
	}

	/**
	 * {@return the number of modules the current module needs to have bound before all of its own
	 * import symbols can be found}
	 */
	public int getModuleDependencies() {
		return moduleDependencies;
	}

	/**
	 * {@return the second reserved value}
	 */
	public int getReserved2() {
		return reserved2;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("module_entry", SIZE);
		struct.setPackingEnabled(true);
		struct.add(DWORD, "drelocs", "text offset into module dynamic relocation array");
		struct.add(DWORD, "imports", "text offset into module import array");
		struct.add(DWORD, "imports_count", "number of entries into module import array");
		struct.add(BYTE, "flags", "currently flags defined: ELAB_REF");
		struct.add(BYTE, "reserved1", null);
		struct.add(WORD, "module_dependencies", null);
		struct.add(DWORD, "reserved2", null);
		struct.setCategoryPath(new CategoryPath("/SOM"));
		return struct;
	}
}
