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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * C13Lines information.  As best as we know, only one of C11Lines or C13Lines (We are actually
 * creating a C13Debug class at a higher level, and making C13Lines be the specific C13Debug
 * information for "type" 0xf2 (and maybe 0xf4) can be found after the symbol information in
 * module debug streams.
 */
public class AbstractLinesC13Section extends C13Section {

	private long offCon; // uint32
	private int segCon; // uint16
	private int flags; // uint16
	private long lenCon; // uint32

	private List<C13FileRecord> fileRecords = new ArrayList<>();

	protected AbstractLinesC13Section(PdbByteReader reader, boolean ignore, TaskMonitor monitor)
			throws PdbException, CancelledException {
		super(ignore);
		if (reader.numRemaining() < 12) {
			throw new PdbException("Not enough data for header");
		}
		offCon = reader.parseUnsignedIntVal();
		segCon = reader.parseUnsignedShortVal();
		flags = reader.parseUnsignedShortVal();
		lenCon = reader.parseUnsignedIntVal();

		boolean hasColumn = ((flags & 0X0001) != 0);

		while (reader.hasMore()) {
			monitor.checkCancelled();
			C13FileRecord fileRecord = C13FileRecord.parse(reader, hasColumn, monitor);
			if (fileRecord == null) {
				break;
			}
			fileRecords.add(fileRecord);
		}
	}

	/**
	 * Returns the offCon value.  Note that we are not certain, but think it is the offset
	 * within the particular memory segment for a chuck of records
	 * @return the offCon value
	 */
	public long getOffCon() {
		return offCon;
	}

	/**
	 * Returns the segment value.  We believe this is the segment that goes with the offCon
	 * value pertaining to a chunk of records
	 * @return the segment
	 */
	public int getSegCon() {
		return segCon;
	}

	/**
	 * Flags for the chunk of records.  We have not determined what any of the flag values
	 * represent
	 * @return the flags
	 */
	public int getFlags() {
		return flags;
	}

	/**
	 * Returns the lenCon value.  We are not certain, but believe this to be the length (bytes
	 * in memory) of the chunk of records
	 * @return the lenCon
	 */
	public long getLenCon() {
		return lenCon;
	}

	/**
	 * Returns a list of file records for this chunk
	 * @return the file records
	 */
	public List<C13FileRecord> getFileRecords() {
		return fileRecords;
	}

	@Override
	public String toString() {
		return String.format(
			"%s: offCon = %ld, segCon = %d, flags = 0x%04x, lenCon = %d; num records = %d",
			getClass().getSimpleName(), offCon, segCon, flags, lenCon, fileRecords.size());
	}

	@Override
	protected void dumpInternal(Writer writer, TaskMonitor monitor)
			throws IOException, CancelledException {
		writer.write(String.format("offCon: 0x%08x segCon: %d flags: 0x%08x lenCon: 0x%08x\n",
			offCon, segCon, flags, lenCon));

		for (C13FileRecord record : fileRecords) {
			monitor.checkCancelled();
			record.dump(writer, offCon);
		}
	}

}
