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
	 * returns the current program, given a tool, if a program is opened;
	 * otherwise returns null.
	 */
	public static Program getCurrentProgram(PluginTool tool) {
		ProgramManager pmService = tool.getService(ProgramManager.class);
		return (pmService == null ? null : pmService.getCurrentProgram());
	}

	/**
	 * Returns true if the program does not contain the analyzed flag. The assumption is that a
	 * non-null value means that the user has already made a decision about analyzing.
	 * 
	 * @param program the program to check for the property
	 * @return true if the program does not contain the analyzed flag
	 */
	public static boolean shouldAskToAnalyze(Program program) {

		// no need to ask if the program can't be saved (i.e. read-only)
		if (program == null || !program.canSave()) {
			return false;
		}

		Options options = program.getOptions(Program.PROGRAM_INFO);
		return !options.contains(Program.ANALYZED);
	}

	/**
	 * Removes the analyzed flag from the program properties.
	 * With this property removed, the user will be prompted to analyze the
	 * program the next time it is opened.
	 * @param program the program containing the property to be removed
	 */
	public static void removeAnalyzedFlag(Program program) {
		int transactionID = program.startTransaction(Program.ANALYZED);
		try {
			Options options = program.getOptions(Program.PROGRAM_INFO);
			options.removeOption(Program.ANALYZED);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
	}

	/**
	 * Sets the analyzed flag to the specified value.
	 * @param program the program to set property
	 * @param analyzed the analyzed flag
	 */
	public static void setAnalyzedFlag(Program program, boolean analyzed) {
		Options options = program.getOptions(Program.PROGRAM_INFO);

		// once the program is analyzed, register the value, so it won't keep writing it to the database.
		if (analyzed && !options.isRegistered(Program.ANALYZED)) {
			options.registerOption(Program.ANALYZED, false, null,
				"Indicates if program has been analyzed");
		}
		int transactionID = program.startTransaction(Program.ANALYZED);
		try {
			options.setBoolean(Program.ANALYZED, analyzed);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
	}
}
