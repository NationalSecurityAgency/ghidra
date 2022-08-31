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

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * C13IlLines information.  This is C13 IL Lines, where "IL" meaning is uncertain... could mean
 * Incremental Link.  MSFT defers parsing to C13Lines, so it is the same format, which we have
 * given to a common parent, {@link AbstractC13Lines}.
 */
public class C13IlLines extends AbstractC13Lines {

	/**
	 * Parse and return a {@link C13IlLines}.
	 * @param reader {@link PdbByteReader} containing the symbol records to deserialize
	 * @param ignore flag indicating whether the record should be ignored
	 * @param monitor {@link TaskMonitor} used for checking cancellation
	 * @return the parsed data
	 * @throws PdbException Upon not enough data left to parse
	 * @throws CancelledException Upon user cancellation
	 */
	static C13IlLines parse(PdbByteReader reader, boolean ignore, TaskMonitor monitor)
			throws PdbException, CancelledException {
		return new C13IlLines(reader, ignore, monitor);
	}

	protected C13IlLines(PdbByteReader reader, boolean ignore, TaskMonitor monitor)
			throws PdbException, CancelledException {
		super(reader, ignore, monitor);
	}

	/**
	 * Dumps this class to a Writer
	 * @param writer {@link Writer} to which to dump the information
	 * @throws IOException Upon IOException writing to the {@link Writer}
	 */
	@Override
	void dump(Writer writer) throws IOException {
		writer.write("C13IlLines--------------------------------------------------\n");
		dumpInternal(writer);
		writer.write("End C13IlLines----------------------------------------------\n");
	}
}
