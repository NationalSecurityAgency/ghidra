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

import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * PDB C13InlineeLines information.
 */
public class C13InlineeLines extends C13Section {

	// These are actually DWORDs, but we are ignoring the unsigned nature and using int.
	private static final int InlineeSourceLineSignature = 0x0;
	private static final int ExtendedInlineeSourceLineSignature = 0x1;

	private int signature; //actually a DWORD (unsigned int)
	private List<InlineeSourceLine> inlineeLines = new ArrayList<>();

	/**
	 * Parse and return a {@link C13InlineeLines}.
	 * @param reader {@link PdbByteReader} containing the symbol records to deserialize
	 * @param ignore flag indicating whether the record should be ignored
	 * @param monitor {@link TaskMonitor} used for checking cancellation
	 * @return the parsed data
	 * @throws PdbException Upon not enough data left to parse
	 * @throws CancelledException Upon user cancellation
	 */
	static C13InlineeLines parse(PdbByteReader reader, boolean ignore, TaskMonitor monitor)
			throws PdbException, CancelledException {
		return new C13InlineeLines(reader, ignore, monitor);
	}

	private static List<InlineeSourceLine> parseInlineeLines(PdbByteReader reader,
			TaskMonitor monitor) throws CancelledException, PdbException {
		List<InlineeSourceLine> lines = new ArrayList<>();
		while (reader.numRemaining() >= InlineeSourceLine.getBaseRecordSize()) {
			monitor.checkCancelled();
			InlineeSourceLine line = new InlineeSourceLine(reader);
			lines.add(line);
		}
		return lines;
	}

	private static List<InlineeSourceLine> parseExtendedInlineeLines(PdbByteReader reader,
			TaskMonitor monitor) throws CancelledException, PdbException {
		List<InlineeSourceLine> lines = new ArrayList<>();
		while (reader.numRemaining() >= ExtendedInlineeSourceLine.getBaseRecordSize()) {
			monitor.checkCancelled();
			ExtendedInlineeSourceLine line = new ExtendedInlineeSourceLine(reader, monitor);
			lines.add(line);
		}
		return lines;
	}

	protected C13InlineeLines(PdbByteReader reader, boolean ignore, TaskMonitor monitor)
			throws PdbException, CancelledException {
		super(ignore);
		signature = reader.parseInt(); //actually a DWORD (unsigned int)
		switch (signature) {
			case InlineeSourceLineSignature:
				inlineeLines = parseInlineeLines(reader, monitor);
				break;
			case ExtendedInlineeSourceLineSignature:
				inlineeLines = parseExtendedInlineeLines(reader, monitor);
				break;
			default:
				inlineeLines = new ArrayList<>();
				break;
		}
		if (reader.hasMore()) {
			Msg.debug(C13InlineeLines.class,
				String.format("Extra inlinee bytes remain for signature: 0x%03x", signature));
		}
	}

	List<InlineeSourceLine> getInlineeLines() {
		return inlineeLines;
	}

	@Override
	public String toString() {
		return String.format(
			"%s: num inlinee lines = %d", getClass().getSimpleName(), inlineeLines.size());
	}

	/**
	 * Dumps this class to a Writer
	 * @param writer {@link Writer} to which to dump the information
	 * @throws IOException Upon IOException writing to the {@link Writer}
	 */
	@Override
	void dump(Writer writer) throws IOException {
		writer.write("C13InlineeLines---------------------------------------------\n");
		writer.write(String.format("Signature: 0x%03x\n", signature));
		for (InlineeSourceLine line : inlineeLines) {
			writer.write(line.toString());
			writer.write('\n');
		}
		writer.write("End C13InlineeLines-----------------------------------------\n");
	}

	static class InlineeSourceLine {
		protected long inlinee; // unsigned 32-bit
		protected int fileId;
		protected int sourceLineNum;

		private static int getBaseRecordSize() {
			return 12;
		}

		InlineeSourceLine(PdbByteReader reader) throws PdbException {
			inlinee = reader.parseUnsignedIntVal();
			fileId = reader.parseInt();
			sourceLineNum = reader.parseInt();
		}

		long getInlinee() {
			return inlinee;
		}

		long getFileId() {
			return fileId;
		}

		long getSourceLineNum() {
			return sourceLineNum;
		}

		@Override
		public String toString() {
			return String.format("0x%09x, 0x%06x, %d", inlinee, fileId, sourceLineNum);
		}
	}

	static class ExtendedInlineeSourceLine extends InlineeSourceLine {

		private static int getBaseRecordSize() {
			return 16;
		}

		private List<Integer> extraFileIds = new ArrayList<>(); // array of longs

		ExtendedInlineeSourceLine(PdbByteReader reader, TaskMonitor monitor)
				throws PdbException, CancelledException {
			super(reader);
			long numExtraFiles = reader.parseUnsignedIntVal(); // unsigned int
			for (long i = 0; i < numExtraFiles; i++) {
				monitor.checkCancelled();
				extraFileIds.add(reader.parseInt());
			}
		}

		int getNumExtraFileIds() {
			return extraFileIds.size();
		}

		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder();
			builder.append(String.format("0x%09x, 0x%06x, %d", inlinee, fileId, sourceLineNum));
			for (Integer id : extraFileIds) {
				builder.append(String.format(" 0x%06x", id));
			}
			return builder.toString();
		}
	}

}
