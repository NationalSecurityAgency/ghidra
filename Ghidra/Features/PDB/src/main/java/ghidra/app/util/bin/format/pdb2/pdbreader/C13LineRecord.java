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

/**
 * A PDB C13 Line Record that is part of a File Record
 */
public class C13LineRecord {
	private long offset; // uint32
	private long bitVals; // uint32
	private C13ColumnRecord columnRecord = null;

	/**
	 * Returns the offset within the segment for this line record
	 * @return the offset
	 */
	public long getOffset() {
		return offset;
	}

	/**
	 * Returns the line number start for this record
	 * @return the line number start
	 */
	public long getLineNumStart() {
		return bitVals & 0xffffffL;
	}

	/**
	 * Returns the delta between the line number start and the line number end (used to calculate
	 * the line number end)
	 * @return the delta between the line number start and the line number end
	 */
	public long getDeltaLineEnd() {
		return (bitVals >> 24) & 0x7fL;
	}

	/**
	 * Returns the column record
	 * @return the column record or {@code null} if one does not exist
	 */
	public C13ColumnRecord getColumnRecord() {
		return columnRecord;
	}

	/**
	 * Returns {@code true} if the line number is that of an statement; else is expression
	 * @return {@code true} if for an statement
	 */
	public boolean isStatement() {
		return (bitVals & 0x80000000L) != 0L;
	}

	/**
	 * Returns {@code true} if the line number is that of an expression; else is statement
	 * @return {@code true} if for an expression
	 */
	public boolean isExpression() {
		return !isStatement();
	}

	/**
	 * Returns {@code true} if is a special line (start is {@code 0xfeefee} or {@code 0xf00f00}).
	 * We do not know how to interpret either of these special line values at this time
	 * @return {@code true} if is a special line
	 */
	public boolean isSpecialLine() {
		long start = getLineNumStart();
		return (start == 0xfeefeeL || start == 0xf00f00L);
	}

	static C13LineRecord parse(PdbByteReader lineReader, PdbByteReader columnReader)
			throws PdbException {
		return new C13LineRecord(lineReader, columnReader);
	}

	private C13LineRecord(PdbByteReader lineReader, PdbByteReader columnReader)
			throws PdbException {
		offset = lineReader.parseUnsignedIntVal();
		bitVals = lineReader.parseUnsignedIntVal();
		if (columnReader != null) { // means hasColumn is true
			columnRecord = C13ColumnRecord.parse(columnReader);
		}
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
