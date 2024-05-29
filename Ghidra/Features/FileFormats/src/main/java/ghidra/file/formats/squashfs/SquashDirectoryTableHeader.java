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
package ghidra.file.formats.squashfs;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SquashDirectoryTableHeader {

	// The number of sub-entries (off by 1, so a "0" really means there is one sub-entry)
	private final long numberOfEntries;

	// Relative to the inode table start, this is the byte offset where the corresponding inode is
	private final long directoryInodeOffset;

	// The base inode number. Sub-entries will store their inodes as an offset to this one (+/-)
	private final long baseInode;

	// A list of sub-entries
	private final List<SquashDirectoryTableEntry> entries;

	/**
	 * Represents an header in the directory table
	 * @param reader A binary reader with pointer index at the start of the header data
	 * @param superBlock The SuperBlock for the current archive
	 * @param monitor Monitor to allow the user to cancel the load
	 * @throws IOException Any read operation failure
	 * @throws CancelledException Archive load was cancelled
	 */
	public SquashDirectoryTableHeader(BinaryReader reader, SquashSuperBlock superBlock,
			TaskMonitor monitor) throws IOException, CancelledException {

		numberOfEntries = reader.readNextUnsignedInt();
		directoryInodeOffset = reader.readNextUnsignedInt();
		baseInode = reader.readNextUnsignedInt();

		// Create a list of entries under this header
		entries = new ArrayList<SquashDirectoryTableEntry>();
		for (int i = 0; i < numberOfEntries + 1; i++) {

			// Check if the user cancelled the load
			monitor.checkCancelled();

			entries.add(new SquashDirectoryTableEntry(reader, superBlock, baseInode));
		}
	}

	public List<SquashDirectoryTableEntry> getEntries() {
		return entries;
	}

	public long getBaseInodeNumber() {
		return baseInode;
	}

	public long getDirectoryInodeOffset() {
		return directoryInodeOffset;
	}

}
