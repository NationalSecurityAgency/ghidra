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
public class InlineeLinesC13Section extends C13Section {

	// These are actually DWORDs, but we are ignoring the unsigned nature and using int.
	private static final int InlineeSourceLineSignature = 0x0;
	private static final int ExtendedInlineeSourceLineSignature = 0x1;

	private int signature; //actually a DWORD (unsigned int)
	private List<C13InlineeSourceLine> inlineeLines = new ArrayList<>();

	/**
	 * Parse and return a {@link InlineeLinesC13Section}.
	 * @param reader {@link PdbByteReader} containing the symbol records to deserialize
	 * @param ignore flag indicating whether the record should be ignored
	 * @param monitor {@link TaskMonitor} used for checking cancellation
	 * @return the parsed data
	 * @throws PdbException Upon not enough data left to parse
	 * @throws CancelledException Upon user cancellation
	 */
	static InlineeLinesC13Section parse(PdbByteReader reader, boolean ignore, TaskMonitor monitor)
			throws PdbException, CancelledException {
		return new InlineeLinesC13Section(reader, ignore, monitor);
	}

	private static List<C13InlineeSourceLine> parseInlineeLines(PdbByteReader reader,
			TaskMonitor monitor) throws CancelledException, PdbException {
		List<C13InlineeSourceLine> lines = new ArrayList<>();
		while (reader.numRemaining() >= C13InlineeSourceLine.getBaseRecordSize()) {
			monitor.checkCancelled();
			C13InlineeSourceLine line = new C13InlineeSourceLine(reader);
			lines.add(line);
		}
		return lines;
	}

	private static List<C13InlineeSourceLine> parseExtendedInlineeLines(PdbByteReader reader,
			TaskMonitor monitor) throws CancelledException, PdbException {
		List<C13InlineeSourceLine> lines = new ArrayList<>();
		while (reader.numRemaining() >= C13ExtendedInlineeSourceLine.getBaseRecordSize()) {
			monitor.checkCancelled();
			C13ExtendedInlineeSourceLine line = new C13ExtendedInlineeSourceLine(reader, monitor);
			lines.add(line);
		}
		return lines;
	}

	private InlineeLinesC13Section(PdbByteReader reader, boolean ignore, TaskMonitor monitor)
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
			Msg.debug(InlineeLinesC13Section.class,
				String.format("Extra inlinee bytes remain for signature: 0x%03x", signature));
		}
	}

	/**
	 * Returns the signature.  Not sure how to interpret the signature at this time
	 * @return the signature
	 */
	public int getSignature() {
		return signature;
	}

	/**
	 * Returns the inlinee source lines
	 * @return the inlinee source lines
	 */
	public List<C13InlineeSourceLine> getInlineeLines() {
		return inlineeLines;
	}

	@Override
	public String toString() {
		return String.format("%s: num inlinee lines = %d", getClass().getSimpleName(),
			inlineeLines.size());
	}

	@Override
	protected void dumpInternal(Writer writer, TaskMonitor monitor)
			throws IOException, CancelledException {
		writer.write(String.format("Signature: 0x%03x\n", signature));
		for (C13InlineeSourceLine line : inlineeLines) {
			monitor.checkCancelled();
			writer.write(line.toString());
			writer.write('\n');
		}
	}

}
