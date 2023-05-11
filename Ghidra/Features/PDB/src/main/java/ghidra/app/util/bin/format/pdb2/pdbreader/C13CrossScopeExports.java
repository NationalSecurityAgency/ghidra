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
 * PDB C13 Cross-Scope Exports information.
 */
public class C13CrossScopeExports extends C13Section {

	private List<CrossScopeExport> crossScopeExports = new ArrayList<>();

	/**
	 * Parse and return a {@link C13CrossScopeExports}.
	 * @param reader {@link PdbByteReader} containing the symbol records to deserialize
	 * @param ignore flag indicating whether the record should be ignored
	 * @param monitor {@link TaskMonitor} used for checking cancellation
	 * @return the parsed data
	 * @throws PdbException Upon not enough data left to parse
	 * @throws CancelledException Upon user cancellation
	 */
	static C13CrossScopeExports parse(PdbByteReader reader, boolean ignore, TaskMonitor monitor)
			throws PdbException, CancelledException {
		return new C13CrossScopeExports(reader, ignore, monitor);
	}

	protected C13CrossScopeExports(PdbByteReader reader, boolean ignore, TaskMonitor monitor)
			throws CancelledException, PdbException {
		super(ignore);
		while (reader.numRemaining() >= CrossScopeExport.getBaseRecordSize()) {
			monitor.checkCancelled();
			CrossScopeExport crossExport = new CrossScopeExport(reader);
			crossScopeExports.add(crossExport);
		}
		if (reader.hasMore()) {
			Msg.debug(C13CrossScopeExports.class,
				String.format("Num Extra C13CrossScopeExports bytes: %d", reader.numRemaining()));
		}
	}

	List<CrossScopeExport> getCrossScopeExports() {
		return crossScopeExports;
	}

	@Override
	public String toString() {
		return String.format("%s: num cross-scope exports = %d", getClass().getSimpleName(),
			crossScopeExports.size());
	}

	/**
	 * Dumps this class to a Writer
	 * @param writer {@link Writer} to which to dump the information
	 * @throws IOException Upon IOException writing to the {@link Writer}
	 */
	@Override
	void dump(Writer writer) throws IOException {
		writer.write("C13CrossScopeExports----------------------------------------\n");
		for (CrossScopeExport crossScopeExport : crossScopeExports) {
			writer.write(crossScopeExport.toString());
			writer.write('\n');
		}
		writer.write("End C13CrossScopeExports------------------------------------\n");
	}

	static class CrossScopeExport {
		private long localId; // unsigned 32-bit
		private long globalId; // unsigned 32-bit

		private static int getBaseRecordSize() {
			return 8;
		}

		CrossScopeExport(PdbByteReader reader) throws PdbException {
			localId = reader.parseUnsignedIntVal();
			globalId = reader.parseUnsignedIntVal();
		}

		long getLocalId() {
			return localId;
		}

		long getGlobalId() {
			return globalId;
		}

		@Override
		public String toString() {
			return String.format("0x%08x, 0x%08x", localId, globalId);
		}
	}

}
