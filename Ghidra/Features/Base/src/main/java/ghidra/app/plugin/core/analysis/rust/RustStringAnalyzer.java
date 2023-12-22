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
package ghidra.app.plugin.core.analysis.rust;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefinedDataIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Splits non-terminated strings into separate strings
 */
public class RustStringAnalyzer extends AbstractAnalyzer {

	private final static String NAME = "Rust String Analyzer";
	private final static String DESCRIPTION = "Analyzer to split rust static strings into slices";

	public RustStringAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.LOW_PRIORITY);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		String name = program.getCompiler();
		return name.contains(RustConstants.RUST_COMPILER);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		DefinedDataIterator dataIterator = DefinedDataIterator.definedStrings(program);

		for (Data data : dataIterator) {
			Address start = data.getAddress();
			int length = data.getLength();

			recurseString(program, start, length);
			monitor.checkCancelled();
		}

		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		// No options
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		// Options changed
	}

	private static void recurseString(Program program, Address start, int maxLen) {
		int newLength = getMaxStringLength(program, start, maxLen);
		if (newLength <= 0) {
			return;
		}

		DataType dt =
			new ArrayDataType(CharDataType.dataType, newLength, CharDataType.dataType.getLength());

		try {
			DataUtilities.createData(program, start, dt, 0,
				DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);

			if (newLength < maxLen) {
				recurseString(program, start.add(newLength), maxLen - newLength);
			}
		}
		catch (Exception e) {
			// Couldn't define string
		}
	}

	/**
	 * Get the number of bytes to the next reference, or the max length
	 * @param program The {@link Program}
	 * @param address The {@link Address}
	 * @param maxLen The maximum length
	 * @return maximum length to create the string
	 */
	private static int getMaxStringLength(Program program, Address address, int maxLen) {
		AddressIterator refIter =
			program.getReferenceManager().getReferenceDestinationIterator(address.next(), true);

		Address next = refIter.next();
		if (next == null) {
			return -1;
		}

		long len = -1;
		try {
			len = next.subtract(address);
			if (len > maxLen) {
				len = maxLen;
			}
			return (int) len;
		}
		catch (IllegalArgumentException e) {
			// bad address subtraction
		}

		return (int) len;
	}
}
