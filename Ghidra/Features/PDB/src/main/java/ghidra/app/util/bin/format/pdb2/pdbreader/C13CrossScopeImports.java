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
 * PDB C13 Cross-Scope Imports information.... also known as Cross-Scope References.
 */
public class C13CrossScopeImports extends C13Section {

	private List<CrossScopeImport> crossScopeImports = new ArrayList<>();

	/**
	 * Parse and return a {@link C13CrossScopeImports}.
	 * @param reader {@link PdbByteReader} containing the symbol records to deserialize
	 * @param ignore flag indicating whether the record should be ignored
	 * @param monitor {@link TaskMonitor} used for checking cancellation
	 * @return the parsed data
	 * @throws PdbException Upon not enough data left to parse
	 * @throws CancelledException Upon user cancellation
	 */
	static C13CrossScopeImports parse(PdbByteReader reader, boolean ignore, TaskMonitor monitor)
			throws PdbException, CancelledException {
		return new C13CrossScopeImports(reader, ignore, monitor);
	}

	protected C13CrossScopeImports(PdbByteReader reader, boolean ignore, TaskMonitor monitor)
			throws CancelledException, PdbException {
		super(ignore);
		while (reader.numRemaining() >= CrossScopeImport.getBaseRecordSize()) {
			monitor.checkCancelled();
			CrossScopeImport crossImport = new CrossScopeImport(reader);
			crossScopeImports.add(crossImport);
		}
		if (reader.hasMore()) {
			Msg.debug(C13CrossScopeExports.class,
				String.format("Num Extra C13CrossScopeExports bytes: %d", reader.numRemaining()));
		}
	}

	List<CrossScopeImport> getCrossScopeImports() {
		return crossScopeImports;
	}

	@Override
	public String toString() {
		return String.format("%s: num cross-scope imports = %d", getClass().getSimpleName(),
			crossScopeImports.size());
	}

	/**
	 * Dumps this class to a Writer
	 * @param writer {@link Writer} to which to dump the information
	 * @throws IOException Upon IOException writing to the {@link Writer}
	 */
	@Override
	void dump(Writer writer) throws IOException {
		writer.write("C13CrossScopeImports----------------------------------------\n");
		for (CrossScopeImport crossScopeImport : crossScopeImports) {
			writer.write(crossScopeImport.toString());
			writer.write('\n');
		}
		writer.write("End C13CrossScopeImports------------------------------------\n");
	}

	static class CrossScopeImport {
		private int offsetObjectFilePath; // the module file; signed 32-bit
		private long numCrossReferences; // unsigned 32-bit
		private List<Long> referenceIds; // Array of unsigned 32-bit values

		private static int getBaseRecordSize() {
			return 8;
		}

		CrossScopeImport(PdbByteReader reader) throws PdbException {
			offsetObjectFilePath = reader.parseInt();
			numCrossReferences = reader.parseUnsignedIntVal();
			referenceIds = new ArrayList<>();
			for (long i = 0; i < numCrossReferences; i++) {
				referenceIds.add(reader.parseUnsignedIntVal());
			}
		}

		long getOffsetObjectFilePath() {
			return offsetObjectFilePath;
		}

		long getNumCrossReferences() {
			return numCrossReferences;
		}

		List<Long> getReferenceIds() {
			return referenceIds;
		}

		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder();
			builder.append(String.format("0x%08x, %5d", offsetObjectFilePath, numCrossReferences));
			for (Long id : referenceIds) {
				builder.append(String.format(" 0x%08x", id));
			}
			return builder.toString();
		}
	}

}
