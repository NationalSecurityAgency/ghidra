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
//Script to compute and print the cyclomatic complexity of the current function.
//@__params_start
//@category Functions
//@toolbar world.png
//@menupath Tools.Scripts Manager.Compute Cyclomatic Complexity
//@__params_end

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.util.CyclomaticComplexity;

public class ComputeCyclomaticComplexity extends GhidraScript {
	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			printerr("no current program");
			return;
		}
		Function function =
			currentProgram.getFunctionManager().getFunctionContaining(currentAddress);
		if (function == null) {
			printerr("no function containing current address " + currentAddress);
			return;
		}
		CyclomaticComplexity cyclomaticComplexity = new CyclomaticComplexity();
		println("complexity: " +
			cyclomaticComplexity.calculateCyclomaticComplexity(function, monitor));
	}
}
