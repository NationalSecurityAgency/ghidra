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
 * Represents a SOM {@code export_entry_ext} structure
 * 
 * @see <a href="https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf">The 32-bit PA-RISC Run-time Architecture Document</a> 
 */
public class SomExportEntryExt implements StructConverter {

	/** The size in bytes of a {@link SomExportEntryExt} */
	public static final int SIZE = 0x14;

	private int size;
	private int dreloc;
	private int sameList;
	private int reserved2;
	private int reserved3;

	/**
	 * Creates a new {@link SomExportEntryExt}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the export extension list
	 * @throws IOException if there was an IO-related error
	 */
	public SomExportEntryExt(BinaryReader reader) throws IOException {
		size = reader.readNextInt();
		dreloc = reader.readNextInt();
		sameList = reader.readNextInt();
		reserved2 = reader.readNextInt();
		reserved3 = reader.readNextInt();
	}

	/**
	 * {@return the size of the export symbol and is only valid for exports of type {@code ST_DATA}
	 */
	public int getSize() {
		return size;
	}

	/**
	 * {@return the start of the dreloc records for the exported symbol}
	 */
	public int getDreloc() {
		return dreloc;
	}

	/**
	 * {@return the circular list of exports that have the same value (physical location) in the
	 * library}
	 */
	public int getSameList() {
		return sameList;
	}

	/**
	 * {@return the second reserved value}
	 */
	public int getReserved2() {
		return reserved2;
	}

	/**
	 * {@return the third reserved value}
	 */
	public int getReserved3() {
		return reserved3;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("export_entry_ext", SIZE);
		struct.setPackingEnabled(true);
		struct.add(DWORD, "size", "export symbol size, data only");
		struct.add(DWORD, "dreloc", "start of dreloc for this symbol");
		struct.add(DWORD, "same_list", "circular list of exports that have the same value");
		struct.add(DWORD, "reserved2", null);
		struct.add(DWORD, "reserved3", null);
		struct.setCategoryPath(new CategoryPath("/SOM"));
		return struct;
	}
}
