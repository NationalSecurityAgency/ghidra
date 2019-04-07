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
//Turns off Function ID and Library Identification analysis before
//auto-analysis whilst running headless Ghidra for import and ingest
//of programs (object files/libraries) for use in creating FID libraries
//@category FunctionID
import ghidra.app.script.GhidraScript;

import java.util.Map;

public class FunctionIDHeadlessPrescript extends GhidraScript {
	// must turn off FID and LID when analyzing libraries for FID
	// creation, in order to avoid corrupting names

	// also, it's important that your loaders have moved object file
	// sections to an appropriate height above 0x0 in order for the
	// scalar operand analyzer to run; we need to identify those
	// references to rule out scalar addresses!

	private static final String FUNCTION_ID_ANALYZER = "Function ID";
	private static final String LIBRARY_IDENTIFICATION = "Library Identification";
	private static final String DEMANGLER_ANALYZER = "Demangler";
	private static final String SCALAR_OPERAND_ANALYZER = "Scalar Operand References";

	@Override
	protected void run() throws Exception {
		Map<String, String> options = getCurrentAnalysisOptionsAndValues(currentProgram);
		if (options.containsKey(FUNCTION_ID_ANALYZER)) {
			setAnalysisOption(currentProgram, FUNCTION_ID_ANALYZER, "false");
		}
		if (options.containsKey(LIBRARY_IDENTIFICATION)) {
			setAnalysisOption(currentProgram, LIBRARY_IDENTIFICATION, "false");
		}
		if (options.containsKey(DEMANGLER_ANALYZER)) {
			setAnalysisOption(currentProgram, DEMANGLER_ANALYZER, "false");
		}
		if (options.containsKey(SCALAR_OPERAND_ANALYZER)) {
			setAnalysisOption(currentProgram, SCALAR_OPERAND_ANALYZER, "true");
		}
	}
}
