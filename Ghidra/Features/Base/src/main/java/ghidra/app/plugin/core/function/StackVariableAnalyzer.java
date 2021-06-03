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
package ghidra.app.plugin.core.function;

import ghidra.app.cmd.function.FunctionStackAnalysisCmd;
import ghidra.app.cmd.function.NewFunctionStackAnalysisCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class StackVariableAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Stack";
	private static final String DESCRIPTION = "Creates stack variables for a function.";

	private boolean doNewStackAnalysis = true;
	private boolean doLocalAnalysis = true;
	private boolean doParameterAnalysis = true;

	public StackVariableAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after().after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		BackgroundCommand cmd;

		if (doNewStackAnalysis) {
			cmd = new NewFunctionStackAnalysisCmd(set, doParameterAnalysis, doLocalAnalysis, false);
		}
		else {
			cmd = new FunctionStackAnalysisCmd(set, doParameterAnalysis, doLocalAnalysis, false);
		}

		cmd.applyTo(program, monitor);
		return true;
	}

	private boolean useOldStackAnalysisByDefault(Program program) {
		Language language = program.getLanguage();
		if (language.getProcessor().equals(Processor.findOrPossiblyCreateProcessor("x86"))) {
			if (language.getLanguageDescription().getSize() == 16) {
				// Prefer using old stack analysis for x86 16-bit with segmented addresses
				return true;
			}
		}
		return false;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(GhidraLanguagePropertyKeys.USE_NEW_FUNCTION_STACK_ANALYSIS,
			!useOldStackAnalysisByDefault(program), null,
			"Use General Stack Reference Propogator (This works best on most processors)");

		options.registerOption("Create Local Variables", doLocalAnalysis, null,
			"Create Function Local stack variables and references");

		options.registerOption("Create Param Variables", doParameterAnalysis, null,
			"Create Function Parameter stack variables and references");
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		doNewStackAnalysis =
			options.getBoolean(GhidraLanguagePropertyKeys.USE_NEW_FUNCTION_STACK_ANALYSIS,
				!useOldStackAnalysisByDefault(program));

		doLocalAnalysis = options.getBoolean("Create Local Variables", doLocalAnalysis);

		doParameterAnalysis = options.getBoolean("Create Param Variables", doParameterAnalysis);
	}

}
