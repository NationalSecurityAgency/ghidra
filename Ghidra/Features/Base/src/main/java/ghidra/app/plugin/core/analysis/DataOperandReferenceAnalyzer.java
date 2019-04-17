/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.analysis;

import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;

/**
 * Check operand references to memory locations looking for
 * Data
 * 
 */
public class DataOperandReferenceAnalyzer extends OperandReferenceAnalyzer {
	private static final String NAME = "Data Reference";
	private static final String DESCRIPTION = "Analyzes data referenced by data.";

	public DataOperandReferenceAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.DATA_ANALYZER);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after().after());
	}

	@Override
	protected void createFunctions(Program program, AddressSet functionStarts) {
		// don't ever create a function from a data pointer
	}
}
