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

import ghidra.app.services.AnalysisPriority;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskMonitor;

/**
 * This analyzer creates only functions that are thunks early in the analysis pipeline.
 */

public class CreateThunkAnalyzer extends FunctionAnalyzer {
	private static final String FIND_THUNKS_STARTS_MSG = "Create Thunks : ";

	private static final String OPTION_NAME_CREATE_THUNKS_EARLY = "Create Thunks Early";
	private static final String OPTION_DESCRIPTION_CREATE_THUNKS_EARLY =
		"If checked, create thunk functions early in analysis flow.";
	private static final boolean OPTION_DEFAULT_CREATE_THUNKS_EARLY_ENABLED = true;

	public CreateThunkAnalyzer() {
		super();
		setPriority(AnalysisPriority.BLOCK_ANALYSIS.after().after());
		setDefaultEnablement(true);
		createOnlyThunks = OPTION_DEFAULT_CREATE_THUNKS_EARLY_ENABLED;
		analysisMessage = FIND_THUNKS_STARTS_MSG;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		if (!createOnlyThunks) {
			return true;
		}
		return super.added(program, set, monitor, log);
	}

	@Override
	public void registerOptions(Options options, Program prog) {
		HelpLocation helpLocation = new HelpLocation("AutoAnalysisPlugin",
			"Auto_Analysis_Option_Instruction" + getAnalysisType());

		options.registerOption(OPTION_NAME_CREATE_THUNKS_EARLY, createOnlyThunks, null,
			OPTION_DESCRIPTION_CREATE_THUNKS_EARLY);
	}

	@Override
	public void optionsChanged(Options options, Program prog) {
		createOnlyThunks = options.getBoolean(OPTION_NAME_CREATE_THUNKS_EARLY, createOnlyThunks);
	}
}
