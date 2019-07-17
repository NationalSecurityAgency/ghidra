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
package ghidra.app.plugin.core.analysis;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.parallel.DecompileConfigurer;
import ghidra.program.model.listing.Program;

/**
 * A configurer for performing calling convention analysis.
 */
public class ConventionAnalysisDecompileConfigurer implements DecompileConfigurer {

	private Program program;

	ConventionAnalysisDecompileConfigurer(Program p) {
		this.program = p;
	}

	@Override
	public void configure(DecompInterface decompiler) {
		decompiler.toggleCCode(false);
		decompiler.toggleSyntaxTree(false); // only recovering the calling convention, no syntax tree needed
		decompiler.setSimplificationStyle("paramid");

		// Set decompiler up with default options for now and any grabbed from the program.
		// TODO: this should use the options from the tool somehow.
		//       unfortunately what is necessary is not here.
		DecompileOptions opts = new DecompileOptions();

		// turn off elimination of dead code, switch could be there.
		opts.setEliminateUnreachable(false);
		opts.grabFromProgram(program);
		decompiler.setOptions(opts);
	}

}
