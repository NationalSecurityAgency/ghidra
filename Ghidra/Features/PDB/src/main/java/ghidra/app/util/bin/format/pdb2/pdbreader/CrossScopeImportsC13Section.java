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
public class CrossScopeImportsC13Section extends C13Section {

	private List<C13CrossScopeImport> crossScopeImports = new ArrayList<>();

	/**
	 * Parse and return a {@link CrossScopeImportsC13Section}.
	 * @param reader {@link PdbByteReader} containing the symbol records to deserialize
	 * @param ignore flag indicating whether the record should be ignored
	 * @param monitor {@link TaskMonitor} used for checking cancellation
	 * @return the parsed data
	 * @throws PdbException Upon not enough data left to parse
	 * @throws CancelledException Upon user cancellation
	 */
	static CrossScopeImportsC13Section parse(PdbByteReader reader, boolean ignore,
			TaskMonitor monitor)
			throws PdbException, CancelledException {
		return new CrossScopeImportsC13Section(reader, ignore, monitor);
	}

	private CrossScopeImportsC13Section(PdbByteReader reader, boolean ignore, TaskMonitor monitor)
			throws CancelledException, PdbException {
		super(ignore);
		while (reader.numRemaining() >= C13CrossScopeImport.getBaseRecordSize()) {
			monitor.checkCancelled();
			C13CrossScopeImport crossImport = new C13CrossScopeImport(reader);
			crossScopeImports.add(crossImport);
		}
		if (reader.hasMore()) {
			Msg.debug(CrossScopeExportsC13Section.class,
				String.format("Num Extra C13CrossScopeExports bytes: %d", reader.numRemaining()));
		}
	}

	/**
	 * Returns the cross-scope imports
	 * @return the cross-scope imports
	 */
	public List<C13CrossScopeImport> getCrossScopeImports() {
		return crossScopeImports;
	}

	@Override
	public String toString() {
		return String.format("%s: num cross-scope imports = %d", getClass().getSimpleName(),
			crossScopeImports.size());
	}

	@Override
	protected void dumpInternal(Writer writer, TaskMonitor monitor)
			throws IOException, CancelledException {
		for (C13CrossScopeImport crossScopeImport : crossScopeImports) {
			monitor.checkCancelled();
			writer.write(crossScopeImport.toString());
			writer.write('\n');
		}
	}

}
