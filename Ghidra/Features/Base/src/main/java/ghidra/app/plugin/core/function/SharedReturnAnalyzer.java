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

import ghidra.app.cmd.analysis.SharedReturnAnalysisCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.GhidraLanguagePropertyKeys;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Identifies functions to which Jump references exist and converts the
 * associated branching instruction flow to a CALL-RETURN
 */
public class SharedReturnAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Shared Return Calls";
	protected static final String DESCRIPTION =
		"Converts branches to calls, followed by an immediate return, when the destination is a function.  " +
			"Since this analysis is triggered by the creation of the destination function, " +
			"the one-shot analysis action can be used if functions were created while this " +
			"analyzer was disabled or not present.";

	private final static String OPTION_NAME_ASSUME_CONTIGUOUS_FUNCTIONS =
		"Assume Contiguous Functions Only";

	private final static String OPTION_NAME_CONSIDER_CONDITIONAL_BRANCHES_FUNCTIONS =
		"Allow Conditional Jumps";

	private static final String OPTION_DESCRIPTION_ASSUME_CONTIGUOUS_FUNCTIONS =
		"Signals to assume all function bodies are contiguous " +
			"and all jumps across other functions should be treated as a call-return.";

	private static final String OPTION_DESCRIPTION_CONSIDER_CONDITIONAL_BRANCHES_FUNCTIONS =
		"Signals to allow conditional jumps to be consider for " +
			"shared return jumps to other functions.";

	private final static boolean OPTION_DEFAULT_ASSUME_CONTIGUOUS_FUNCTIONS_ENABLED = false;
	private final static boolean OPTION_DEFAULT_CONSIDER_CONDITIONAL_BRANCHES_ENABLED = false;

	private boolean assumeContiguousFunctions = OPTION_DEFAULT_ASSUME_CONTIGUOUS_FUNCTIONS_ENABLED;
	private boolean considerConditionalBranches =
		OPTION_DEFAULT_CONSIDER_CONDITIONAL_BRANCHES_ENABLED;

	public SharedReturnAnalyzer() {
		this(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
	}

	public SharedReturnAnalyzer(String name, String description, AnalyzerType analyzerType) {
		super(name, description, analyzerType);
		setPriority(AnalysisPriority.CODE_ANALYSIS.before().before());
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		SharedReturnAnalysisCmd cmd = new SharedReturnAnalysisCmd(set, assumeContiguousFunctions,
			considerConditionalBranches);
		cmd.applyTo(program);

		return true;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		Language language = program.getLanguage();

		boolean sharedReturnEnabled = language.getPropertyAsBoolean(
			GhidraLanguagePropertyKeys.ENABLE_SHARED_RETURN_ANALYSIS, true);

		return sharedReturnEnabled;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		HelpLocation helpLocation = new HelpLocation("AutoAnalysisPlugin",
			"Auto_Analysis_Option_Instructions");

		options.registerOption(OPTION_NAME_ASSUME_CONTIGUOUS_FUNCTIONS,
			OPTION_DEFAULT_ASSUME_CONTIGUOUS_FUNCTIONS_ENABLED, helpLocation,
			OPTION_DESCRIPTION_ASSUME_CONTIGUOUS_FUNCTIONS);

		options.registerOption(OPTION_NAME_CONSIDER_CONDITIONAL_BRANCHES_FUNCTIONS,
			OPTION_DEFAULT_CONSIDER_CONDITIONAL_BRANCHES_ENABLED, helpLocation,
			OPTION_DESCRIPTION_CONSIDER_CONDITIONAL_BRANCHES_FUNCTIONS);
	}

	@Override
	public void optionsChanged(Options options, Program program) {

		assumeContiguousFunctions = options.getBoolean(OPTION_NAME_ASSUME_CONTIGUOUS_FUNCTIONS,
			OPTION_DEFAULT_ASSUME_CONTIGUOUS_FUNCTIONS_ENABLED);

		considerConditionalBranches =
			options.getBoolean(OPTION_NAME_CONSIDER_CONDITIONAL_BRANCHES_FUNCTIONS,
				OPTION_DEFAULT_CONSIDER_CONDITIONAL_BRANCHES_ENABLED);

	}

}
