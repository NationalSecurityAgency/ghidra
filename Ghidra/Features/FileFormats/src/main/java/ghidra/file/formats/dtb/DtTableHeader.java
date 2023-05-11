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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Class to represent a Device Tree (DT) Table Header. 
 * 
 * @see <a href="https://source.android.com/devices/architecture/dto/partitions">devices/architecture/dto/partitions</a>
 * 
 * @see <a href="https://github.com/u-boot/u-boot/blob/master/include/dt_table.h#L19">master/include/dt_table.h</a>
 */
public class DtTableHeader implements StructConverter {

	private int magic;
	private int total_size;
	private int header_size;
	private int dt_entry_size;
	private int dt_entry_count;
	private int dt_entries_offset;
	private int page_size;
	private int version;

	private List<DtTableEntry> _entries = new ArrayList<>();

	public DtTableHeader(BinaryReader reader) throws IOException {
		if (!reader.isBigEndian()) {
			throw new IOException("DTB is always big endian.");
		}

		magic = reader.readNextInt();
		if ( magic != DtConstants.DT_TABLE_MAGIC) {
			throw new IOException("Invalid DTB Header magic.");
		}

		total_size = reader.readNextInt();
		header_size = reader.readNextInt();
		dt_entry_size = reader.readNextInt();
		dt_entry_count = reader.readNextInt();
		dt_entries_offset = reader.readNextInt();
		page_size = reader.readNextInt();
		version = reader.readNextInt();

		reader.setPointerIndex(dt_entries_offset);
		for (int i = 0; i < dt_entry_count; ++i) {
			_entries.add(new DtTableEntry(reader));
		}
	}

	/**
	 * Returns the Device Tree (DT) magic value.
	 * @return the Device Tree (DT) magic value
	 */
	public int getMagic() {
		return magic;
	}

	/**
	 * Returns the Device Tree (DT) total size.
	 * @return the Device Tree (DT) total size
	 */
	public int getTotalSize() {
		return total_size;
	}

	/**
	 * Returns the Device Tree (DT) header size.
	 * @return the Device Tree (DT) header size
	 */
	public int getHeaderSize() {
		return header_size;
	}

	/**
	 * Returns the Device Tree (DT) entry size.
	 * @return the Device Tree (DT) entry size
	 */
	public int getDtEntrySize() {
		return dt_entry_size;
	}

	/**
	 * Returns the Device Tree (DT) entry count.
	 * @return the Device Tree (DT) entry count
	 */
	public int getDtEntryCount() {
		return dt_entry_count;
	}

	/**
	 * Returns the Device Tree (DT) entries offset.
	 * @return the Device Tree (DT) entries offset
	 */
	public int getDtEntriesOffset() {
		return dt_entries_offset;
	}

	/**
	 * Returns the Device Tree (DT) page size.
	 * @return the Device Tree (DT) page size
	 */
	public int getPageSize() {
		return page_size;
	}

	/**
	 * Returns the Device Tree (DT) version.
	 * @return the Device Tree (DT) version
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * Returns the Device Tree (DT) entries.
	 * @return the Device Tree (DT) entries
	 */
	public List<DtTableEntry> getEntries() {
		return _entries;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}
}
