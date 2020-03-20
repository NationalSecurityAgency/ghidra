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

import ghidra.app.cmd.function.DecompilerParameterIdCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.PeLoader;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskMonitor;

public class DecompilerFunctionAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Decompiler Parameter ID";
	private static final String DESCRIPTION =
		"Creates parameter and local variables for a Function using Decompiler." + "\n" +
			"WARNING: This can take a SIGNIFICANT Amount of Time!\n" +
			"         Turned off by default for large programs" + "\n" +
			"You can run this later using \"Analysis->Decompiler Parameter ID\"";

	private static final long MEDIUM_SIZE_PROGRAM = (2 * 1024 * 1024);

	private static final String ENABLED_PROPERTY = "DecompilerParameterAnalyzer.enabled";
	private static final String OPTION_NAME_CLEAR_LEVEL = "Analysis Clear Level";
	private static final String OPTION_NAME_COMMIT_DATA_TYPES = "Commit Data Types";
	private static final String OPTION_NAME_COMMIT_VOID_RETURN = "Commit Void Return Values";
	private static final String OPTION_NAME_DECOMPILER_TIMEOUT_SECS =
		"Analysis Decompiler Timeout (sec)";

	private static final String OPTION_DESCRIPTION_CLEAR_LEVEL =
		"Set level for amount of existing parameter data to clear";
	private static final String OPTION_DESCRIPTION_COMMIT_DATA_TYPES =
		"Turn on to commit data types";
	private static final String OPTION_DESCRIPTION_COMMIT_VOID_RETURN =
		"Turn on to lock in 'void' return values";
	private static final String OPTION_DESCRIPTION_DECOMPILER_TIMEOUT_SECS =
		"Set timeout in seconds for analyzer decompiler calls.";

	//Default that we want must be first in this list.
	private static final SourceType OPTION_DEFAULT_CLEAR_LEVEL = SourceType.ANALYSIS;
	private static final boolean OPTION_DEFAULT_COMMIT_DATA_TYPES = true;
	private static final boolean OPTION_DEFAULT_COMMIT_VOID_RETURN = false;
	public static final int OPTION_DEFAULT_DECOMPILER_TIMEOUT_SECS = 60;

	private SourceType sourceTypeClearLevelOption = OPTION_DEFAULT_CLEAR_LEVEL;
	private boolean commitDataTypesOption = OPTION_DEFAULT_COMMIT_DATA_TYPES;
	private boolean commitVoidReturnOption = OPTION_DEFAULT_COMMIT_VOID_RETURN;
	private int decompilerTimeoutSecondsOption = OPTION_DEFAULT_DECOMPILER_TIMEOUT_SECS;

	public DecompilerFunctionAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after());
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		DecompilerParameterIdCmd cmd = new DecompilerParameterIdCmd(NAME, set,
			sourceTypeClearLevelOption, commitDataTypesOption, commitVoidReturnOption,
			decompilerTimeoutSecondsOption);
		cmd.applyTo(program, monitor);
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().supportsPcode();
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		if (isDisabledFromProperty()) {
			return false;
		}

		long numAddr = program.getMemory().getNumAddresses();

		// only do for windows by default, windows has good type info
		return (numAddr < MEDIUM_SIZE_PROGRAM) &&
			PeLoader.PE_NAME.equals(program.getExecutableFormat());
	}

	private boolean isDisabledFromProperty() {

		String defaultEnabledProperty = System.getProperty(ENABLED_PROPERTY);
		if (defaultEnabledProperty == null) {
			return false;
		}

		boolean isEnabled = Boolean.parseBoolean(defaultEnabledProperty);
		return !isEnabled;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		HelpLocation helpLocation = new HelpLocation("AutoAnalysisPlugin",
			"Decompiler_Parameter_ID_Analyzer");

		options.registerOption(OPTION_NAME_CLEAR_LEVEL, SourceType.ANALYSIS, helpLocation,
			OPTION_DESCRIPTION_CLEAR_LEVEL);

		options.registerOption(OPTION_NAME_COMMIT_DATA_TYPES, commitDataTypesOption, helpLocation,
			OPTION_DESCRIPTION_COMMIT_DATA_TYPES);

		options.registerOption(OPTION_NAME_COMMIT_VOID_RETURN, commitVoidReturnOption, helpLocation,
			OPTION_DESCRIPTION_COMMIT_VOID_RETURN);

		options.registerOption(OPTION_NAME_DECOMPILER_TIMEOUT_SECS, decompilerTimeoutSecondsOption,
			helpLocation, OPTION_DESCRIPTION_DECOMPILER_TIMEOUT_SECS);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		sourceTypeClearLevelOption =
			options.getEnum(OPTION_NAME_CLEAR_LEVEL, SourceType.ANALYSIS);

		decompilerTimeoutSecondsOption =
			options.getInt(OPTION_NAME_DECOMPILER_TIMEOUT_SECS, decompilerTimeoutSecondsOption);

		commitDataTypesOption =
			options.getBoolean(OPTION_NAME_COMMIT_DATA_TYPES, commitDataTypesOption);

		commitVoidReturnOption =
			options.getBoolean(OPTION_NAME_COMMIT_VOID_RETURN, commitVoidReturnOption);
	}
}
