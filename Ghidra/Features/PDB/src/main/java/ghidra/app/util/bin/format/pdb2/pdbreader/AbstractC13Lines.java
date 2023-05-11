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
public class AbstractC13Lines extends C13Section {

	private long offCon; // uint32
	private int segCon; // uint16
	private int flags; // uint16
	private long lenCon; // uint32

	private List<FileRecord> fileRecords = new ArrayList<>();

	protected AbstractC13Lines(PdbByteReader reader, boolean ignore, TaskMonitor monitor)
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
			FileRecord fileRecord = FileRecord.parse(reader, hasColumn, monitor);
			if (fileRecord == null) {
				break;
			}
			fileRecords.add(fileRecord);
		}
	}

	long getOffCon() {
		return offCon;
	}

	int getSegCon() {
		return segCon;
	}

	int getFlags() {
		return flags;
	}

	long getLenCon() {
		return lenCon;
	}

	@Override
	public String toString() {
		return String.format(
			"%s: offCon = %ld, segCon = %d, flags = 0x%04x, lenCon = %d; num records = %d",
			getClass().getSimpleName(), offCon, segCon, flags, lenCon, fileRecords.size());
	}

	/**
	 * Dumps this class to a Writer
	 * @param writer {@link Writer} to which to dump the information
	 * @throws IOException Upon IOException writing to the {@link Writer}
	 */
	@Override
	void dump(Writer writer) throws IOException {
		writer.write("C13Lines----------------------------------------------------\n");
		dumpInternal(writer);
		writer.write("End C13Lines------------------------------------------------\n");
	}

	protected void dumpInternal(Writer writer) throws IOException {
		writer.write(String.format("offCon: 0x%08x segCon: %d flags: 0x%08x lenCon: 0x%08x\n",
			offCon, segCon, flags, lenCon));

		for (FileRecord record : fileRecords) {
			record.dump(writer, offCon);
		}
	}

	static class FileRecord {
		private long fileId; // uint32
		private long nLines; // uint32
		private long lenFileBlock; // uint32
		private List<LineRecord> lineRecords = new ArrayList<>();

		static FileRecord parse(PdbByteReader reader, boolean hasColumn, TaskMonitor monitor)
				throws PdbException {
			return new FileRecord(reader, hasColumn, monitor);
		}

		private FileRecord(PdbByteReader reader, boolean hasColumn, TaskMonitor monitor)
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
				LineRecord lineRecord = LineRecord.parse(lineReader, columnReader);
				lineRecords.add(lineRecord);
			}
		}

		long getFileId() {
			return fileId;
		}

		long getNLines() {
			return nLines;
		}

		long getLenFileBlock() {
			return lenFileBlock;
		}

		List<LineRecord> getLineRecords() {
			return lineRecords;
		}

		void dump(Writer writer, long offCon) throws IOException {
			writer.write(String.format("fileId: %06x, nLines: %d, lenFileBlock: %d\n",
				getFileId(), getNLines(), getLenFileBlock()));
			for (int i = 0; i < getNLines(); i++) {
				List<LineRecord> records = getLineRecords();
				records.get(i).dump(writer, offCon);
				writer.write("\n");
			}
		}
	}

	static class LineRecord {
		private long offset; // uint32
		private long bitVals; // uint32
		private ColumnRecord columnRecord = null;

		long getOffset() {
			return offset;
		}

		long getBitVals() {
			return bitVals;
		}

		long getLineNumStart() {
			return bitVals & 0xffffffL;
		}

		long getDeltaLineEnd() {
			return (bitVals >> 24) & 0x7fL;
		}

		ColumnRecord getColumnRecord() {
			return columnRecord;
		}

		/**
		 * Returns true if the line number is that of an statement
		 * @return true if for an statement
		 */
		boolean isStatement() {
			return (bitVals & 0x80000000L) != 0L;
		}

		/**
		 * Returns true if the line number is that of an expression
		 * @return true if for an expression
		 */
		boolean isExpression() {
			return !isStatement();
		}

		static LineRecord parse(PdbByteReader lineReader, PdbByteReader columnReader)
				throws PdbException {
			return new LineRecord(lineReader, columnReader);
		}

		private LineRecord(PdbByteReader lineReader, PdbByteReader columnReader)
				throws PdbException {
			offset = lineReader.parseUnsignedIntVal();
			bitVals = lineReader.parseUnsignedIntVal();
			if (columnReader != null) { // means hasColumn is true
				columnRecord = ColumnRecord.parse(columnReader);
			}
		}

		private boolean isSpecialLine() {
			long start = getLineNumStart();
			return (start == 0xfeefeeL || start == 0xf00f00L);
		}

		void dump(Writer writer, long offCon) throws IOException {
			String lineStart = (isSpecialLine() ? String.format("%06x", getLineNumStart())
					: String.format("%d", getLineNumStart()));
			if (columnRecord != null) {
				if (columnRecord.getOffsetColumnEnd() != 0L) {
					writer.write(String.format("%5d:%5d-%5d-%5d 0x%08x %s", getLineNumStart(),
						columnRecord.getOffsetColumnStart(), getLineNumStart() + getDeltaLineEnd(),
						columnRecord.getOffsetColumnEnd(), getOffset() + offCon,
						(isStatement() ? "Statement" : "Expression")));
				}
				else {
					writer.write(String.format("%s-%5d 0x%08x %s", lineStart,
						columnRecord.getOffsetColumnStart(), getOffset() + offCon,
						(isStatement() ? "Statement" : "Expression")));
				}
			}
			else {
				writer.write(String.format("%s 0x%08x %s", lineStart, getOffset() + offCon,
					(isStatement() ? "Statement" : "Expression")));
			}
		}
	}

	static class ColumnRecord {
		private int offsetColumnStart; // unsigned short
		private int offsetColumnEnd; // unsigned short

		int getOffsetColumnStart() {
			return offsetColumnStart;
		}

		int getOffsetColumnEnd() {
			return offsetColumnEnd;
		}

		static ColumnRecord parse(PdbByteReader reader) throws PdbException {
			return new ColumnRecord(reader);
		}

		private ColumnRecord(PdbByteReader reader) throws PdbException {
			offsetColumnStart = reader.parseUnsignedShortVal();
			offsetColumnEnd = reader.parseUnsignedShortVal();
		}

		@Override
		public String toString() {
			return String.format("Start: 0x%04x, End: 0x%04x", getOffsetColumnStart(),
				getOffsetColumnEnd());
		}
	}

}
