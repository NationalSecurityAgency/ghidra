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

import ghidra.util.task.TaskMonitor;

/**
 * A PDB C13 File Record pertaining to source line information
 */
public class C13FileRecord {
	private long fileId; // uint32
	private long nLines; // uint32
	private long lenFileBlock; // uint32
	private List<C13LineRecord> lineRecords = new ArrayList<>();

	static C13FileRecord parse(PdbByteReader reader, boolean hasColumn, TaskMonitor monitor)
			throws PdbException {
		return new C13FileRecord(reader, hasColumn, monitor);
	}

	private C13FileRecord(PdbByteReader reader, boolean hasColumn, TaskMonitor monitor)
			throws PdbException {
		if (reader.numRemaining() < 12) {
			throw new PdbException("Not enough data for FileRecord header");
		}
		fileId = reader.parseUnsignedIntVal();
		nLines = reader.parseUnsignedIntVal();
		lenFileBlock = reader.parseUnsignedIntVal();

		long lenMinusHeader = lenFileBlock - 12; // 12 is size of header
		Long x = nLines;
		int nLinesI = x.intValue();
		int sizeLines = nLinesI * 8;
		int sizeColumns = nLinesI * (hasColumn ? 4 : 0);
		int sizeRequired = sizeLines + sizeColumns;

		// was test ">" but both are suspect... not all records might have the columns
		if (lenMinusHeader != sizeRequired) {
			throw new PdbException("Corrupt FileRecord");
		}
		if (reader.numRemaining() < sizeRequired) {
			throw new PdbException("Not enough data for FileRecord records");
		}

		PdbByteReader lineReader = reader.getSubPdbByteReader(sizeLines);
		PdbByteReader columnReader =
			(hasColumn ? reader.getSubPdbByteReader(sizeColumns) : null);

		for (int i = 0; i < nLines; i++) {
			C13LineRecord lineRecord = C13LineRecord.parse(lineReader, columnReader);
			lineRecords.add(lineRecord);
		}
	}

	/**
	 * Returns the file ID
	 * @return the file ID
	 */
	public int getFileId() {
		// We will need to watch for this to blow and then re-evaluate.  I doubt that the list
		// of names needs more than 2GB of characters
		Long v = fileId;
		return v.intValue();
		//return fileId;
	}

	/**
	 * Returns the number of lines for the file record
	 * @return the number of lines
	 */
	public long getNLines() {
		return nLines;
	}

	/**
	 * Returns the length of the block of records
	 * @return the length
	 */
	public long getLenFileBlock() {
		return lenFileBlock;
	}

	/**
	 * Returns the list of line records for the file record
	 * @return the line records
	 */
	public List<C13LineRecord> getLineRecords() {
		return lineRecords;
	}

	void dump(Writer writer, long offCon) throws IOException {
		writer.write(String.format("fileId: %06x, nLines: %d, lenFileBlock: %d\n", getFileId(),
			getNLines(), getLenFileBlock()));
		for (int i = 0; i < getNLines(); i++) {
			List<C13LineRecord> records = getLineRecords();
			records.get(i).dump(writer, offCon);
			writer.write("\n");
		}
	}
}
