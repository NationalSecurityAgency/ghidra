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

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * C13IlLines information.  This is C13 IL Lines, where "IL" meaning is uncertain... could mean
 * Incremental Link.  MSFT defers parsing to C13Lines, so it is the same format, which we have
 * given to a common parent, {@link AbstractLinesC13Section}.
 */
public class IlLinesC13Section extends AbstractLinesC13Section {

	/**
	 * Parse and return a {@link IlLinesC13Section}.
	 * @param reader {@link PdbByteReader} containing the symbol records to deserialize
	 * @param ignore flag indicating whether the record should be ignored
	 * @param monitor {@link TaskMonitor} used for checking cancellation
	 * @return the parsed data
	 * @throws PdbException Upon not enough data left to parse
	 * @throws CancelledException Upon user cancellation
	 */
	static IlLinesC13Section parse(PdbByteReader reader, boolean ignore, TaskMonitor monitor)
			throws PdbException, CancelledException {
		return new IlLinesC13Section(reader, ignore, monitor);
	}

	private IlLinesC13Section(PdbByteReader reader, boolean ignore, TaskMonitor monitor)
			throws PdbException, CancelledException {
		super(reader, ignore, monitor);
	}

}
