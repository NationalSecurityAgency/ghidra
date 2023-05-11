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
package ghidra.program.util;

import ghidra.app.services.ProgramManager;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

public class GhidraProgramUtilities {
	private GhidraProgramUtilities() {
	}

	/**
	 * Returns the current program for the given tool or null if no program is open.
	 * @param tool the tool get get the current program for
	 * @return the current program for the given tool or null if no program is open
	 */
	public static Program getCurrentProgram(PluginTool tool) {
		ProgramManager pmService = tool.getService(ProgramManager.class);
		return (pmService == null ? null : pmService.getCurrentProgram());
	}

	/**
	 * Returns true if the user should be asked to analyze. They will only be asked if the program
	 * hasn't already been analyzed (analyzed flag property is false or null) or the
	 * "ask to analyze" flag property is true or null (default is true unless explicitly set to 
	 * false).
	 * 
	 * @param program the program to check for the property
	 * @return true if the user should be prompted to analyze the program
	 */
	public static boolean shouldAskToAnalyze(Program program) {

		// no need to ask if the program can't be saved (i.e. read-only)
		if (program == null || !program.canSave()) {
			return false;
		}

		Options options = program.getOptions(Program.PROGRAM_INFO);
		// older programs don't have a "Ask" property, so check analyzed flag
		boolean isAnalyzed = options.getBoolean(Program.ANALYZED_OPTION_NAME, false);
		if (isAnalyzed) {
			return false;
		}
		return options.getBoolean(Program.ASK_TO_ANALYZE_OPTION_NAME, true);
	}

	/**
	 * Resets the analysis flags to the program defaults
	 * With this reset, the user will be prompted to analyze the
	 * program the next time it is opened.
	 * @param program the program whose analysis flags should be reset
	 */
	public static void resetAnalysisFlags(Program program) {
		int transactionID = program.startTransaction("Reset Analysis Flags");

		try {
			Options options = program.getOptions(Program.PROGRAM_INFO);
			options.removeOption(Program.ANALYZED_OPTION_NAME);
			options.removeOption(Program.ASK_TO_ANALYZE_OPTION_NAME);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
	}

	/**
	 * Marks the program has having been analyzed
	 * @param program the program to set property
	 */
	public static void markProgramAnalyzed(Program program) {
		Options options = program.getOptions(Program.PROGRAM_INFO);

		int transactionID = program.startTransaction("Mark Program Analyzed");
		try {
			options.setBoolean(Program.ANALYZED_OPTION_NAME, true);
			options.setBoolean(Program.ASK_TO_ANALYZE_OPTION_NAME, false);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
	}

	public static void markProgramNotToAskToAnalyze(Program program) {
		Options options = program.getOptions(Program.PROGRAM_INFO);

		int transactionID = program.startTransaction("Mark Program To Not Ask To Analyze");
		try {
			options.setBoolean(Program.ASK_TO_ANALYZE_OPTION_NAME, false);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
	}

	/**
	 * Returns true if the program has been analyzed at least once.
	 * @param program the program to test to see if it has been analyzed
	 * @return true if the program has been analyzed at least once.
	 */
	public static boolean isAnalyzed(Program program) {
		Options options = program.getOptions(Program.PROGRAM_INFO);

		return options.getBoolean(Program.ANALYZED_OPTION_NAME, false);
	}

}
