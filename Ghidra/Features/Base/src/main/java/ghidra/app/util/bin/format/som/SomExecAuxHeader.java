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
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a SOM {@code som_exec_auxhdr} structure
 * 
 * @see <a href="https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf">The 32-bit PA-RISC Run-time Architecture Document</a> 
 */
public class SomExecAuxHeader extends SomAuxHeader {

	private long execTextSize;
	private long execTextMem;
	private long execTextFile;
	private long execDataSize;
	private long execDataMem;
	private long execDataFile;
	private long execBssSize;
	private long execEntry;
	private long execFlags;
	private long execBssFill;

	/**
	 * Creates a new {@link SomExecAuxHeader}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the auxiliary header
	 * @throws IOException if there was an IO-related error
	 */
	public SomExecAuxHeader(BinaryReader reader) throws IOException {
		super(reader);
		execTextSize = reader.readNextUnsignedInt();
		execTextMem = reader.readNextUnsignedInt();
		execTextFile = reader.readNextUnsignedInt();
		execDataSize = reader.readNextUnsignedInt();
		execDataMem = reader.readNextUnsignedInt();
		execDataFile = reader.readNextUnsignedInt();
		execBssSize = reader.readNextUnsignedInt();
		execEntry = reader.readNextUnsignedInt();
		execFlags = reader.readNextUnsignedInt();
		execBssFill = reader.readNextUnsignedInt();
	}

	/**
	 * {@return the text size in bytes}
	 */
	public long getExecTextSize() {
		return execTextSize;
	}

	/**
	 * {@return the offset of text in memory}
	 */
	public long getExecTextMem() {
		return execTextMem;
	}

	/**
	 * {@return the location of text in file}
	 */
	public long getExecTextFile() {
		return execTextFile;
	}

	/**
	 * {@return the initialized data size in bytes}
	 */
	public long getExecDataSize() {
		return execDataSize;
	}

	/**
	 * {@return the offset of data in memory}
	 */
	public long getExecDataMem() {
		return execDataMem;
	}

	/**
	 * {@return the location of data in file}
	 */
	public long getExecDataFile() {
		return execDataFile;
	}

	/**
	 * {@return the uninitialized data (BSS) size in bytes}
	 */
	public long getExecBssSize() {
		return execBssSize;
	}

	/**
	 * {@return the offset of entrypoint}
	 */
	public long getExecEntry() {
		return execEntry;
	}

	/**
	 * {@return the loader flags}
	 */
	public long getExecFlags() {
		return execFlags;
	}

	/**
	 * {@return BSS initialization value}
	 */
	public long getExecBssFill() {
		return execBssFill;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("som_exec_auxhdr", 0);
		struct.setPackingEnabled(true);
		struct.add(auxId.toDataType(), "som_auxhdr", null);
		struct.add(DWORD, "exec_tsize", "text size in bytes");
		struct.add(DWORD, "exec_tmem", "offset of text in memory");
		struct.add(DWORD, "exec_tfile", "location of text in file");
		struct.add(DWORD, "exec_dsize", "initialized data size in bytes");
		struct.add(DWORD, "exec_dmem", "offset of data in memory");
		struct.add(DWORD, "exec_dfile", "location of data in file");
		struct.add(DWORD, "exec_bsize", "uninitialized data (bss) size in bytes");
		struct.add(DWORD, "exec_entry", "offset of entrypoint");
		struct.add(DWORD, "exec_flags", "loader flags");
		struct.add(DWORD, "exec_bfill", "bss initialization value");
		struct.setCategoryPath(new CategoryPath("/SOM"));
		return struct;
	}
}
