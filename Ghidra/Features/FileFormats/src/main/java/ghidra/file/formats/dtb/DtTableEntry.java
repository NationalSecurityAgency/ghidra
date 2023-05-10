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
package ghidra.file.formats.dtb;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Class to represent a Device Tree (DT) Table Entry. 
 * 
 * @see <a href="https://github.com/u-boot/u-boot/blob/master/include/dt_table.h#L40">master/include/dt_table.h</a>
 */
public class DtTableEntry implements StructConverter {

	private int dt_size;
	private int dt_offset;
	private int id;
	private int rev;
	private int[] custom;

	private FdtHeader _fdtHeader;

	public DtTableEntry(BinaryReader reader) throws IOException {
		if (!reader.isBigEndian()) {
			throw new IOException("DTB is always big endian.");
		}

		dt_size = reader.readNextInt();
		dt_offset = reader.readNextInt();
		id = reader.readNextInt();
		rev = reader.readNextInt();
		custom = reader.readNextIntArray(4);

		BinaryReader clonedReader = reader.clone(dt_offset);
		if (clonedReader.peekNextInt() == FdtConstants.FDT_MAGIC) {
			_fdtHeader = new FdtHeader(clonedReader);
		}
	}

	/**
	 * Returns the Device Tree (DT) Table Size.
	 * @return the Device Tree (DT) Table Size
	 */
	public int getDtSize() {
		return dt_size;
	}

	/**
	 * Returns the Device Tree (DT) Table Offset.
	 * @return the Device Tree (DT) Table Offset
	 */
	public int getDtOffset() {
		return dt_offset;
	}

	/**
	 * Returns the Device Tree (DT) Table ID.
	 * @return the Device Tree (DT) Table ID
	 */
	public int getId() {
		return id;
	}

	/**
	 * Returns the Device Tree (DT) Table Revision.
	 * @return the Device Tree (DT) Table Revision
	 */
	public int getRev() {
		return rev;
	}

	/**
	 * Returns the Device Tree (DT) Table Custom Bytes.
	 * @return the Device Tree (DT) Table Custom Bytes
	 */
	public int[] getCustom() {
		return custom;
	}

	/**
	 * Returns the FDT Header.
	 * @return the FDT Header
	 */
	public FdtHeader getFdtHeader() {
		return _fdtHeader;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}
}
