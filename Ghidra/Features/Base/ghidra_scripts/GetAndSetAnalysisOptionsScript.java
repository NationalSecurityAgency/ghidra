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
// Shows examples of how to get, set, and reset analysis options using the GhidraScript API.
//
//@category Examples

import ghidra.app.script.GhidraScript;

import java.util.*;

public class GetAndSetAnalysisOptionsScript extends GhidraScript {

	@Override
	protected void run() throws Exception {

		Map<String, String> options;

		// Get current state of available analysis options and values
		options = getCurrentAnalysisOptionsAndValues(currentProgram);
		getAndPrintAnalysisOptionsInfo(options);

		// Set analysis options using various available methods
		setSomeOptions();

		println("\n==> Resetting some options to their default values <==");
		resetAnalysisOptions(
			currentProgram,
			Arrays.asList(new String[] { "ASCII Strings.Minimum string length",
				"Decompiler Parameter ID.Prototype Evaluation" }));

		println("\n==> Resetting all options <==");
		resetAllAnalysisOptions(currentProgram);

		// Check whether an analysis option value is equal to the default value
		String trueCase = "LEN_5", falseCase = "LEN_19";

		boolean isThisDefault =
			isAnalysisOptionDefaultValue(currentProgram, "ASCII Strings.Minimum string length",
				trueCase);
		println("Default for ASCII Strings Minimum String Length == " + trueCase + "? " +
			isThisDefault);

		isThisDefault =
			isAnalysisOptionDefaultValue(currentProgram, "ASCII Strings.Minimum string length",
				falseCase);
		println("Default for ASCII Strings Minimum String Length == " + falseCase + "? " +
			isThisDefault);
	}

	private void getAndPrintAnalysisOptionsInfo(Map<String, String> options) {

		Map<String, String> optionDescriptions, optionDefaults;

		// Get descriptions associated with the analysis options
		optionDescriptions =
			getAnalysisOptionDescriptions(currentProgram, new ArrayList<String>(options.keySet()));

		// Get default values associated with the analysis options
		optionDefaults =
			getAnalysisOptionDefaultValues(currentProgram, new ArrayList<String>(options.keySet()));

		// Sort analysis options and print out information about each one
		String[] sortedArray = options.keySet().toArray(new String[0]);
		Arrays.sort(sortedArray);

		String[] choicesForOption;
		StringBuilder printStr;
		String defaultVal;

		for (String option : sortedArray) {

			printStr =
				new StringBuilder("[ Option = " + option + " ] [ Description = " +
					optionDescriptions.get(option) + "  ] ");

			// Get choices (if any) that are available for this analysis option
			//choicesForOption = getAnalysisOptionChoices(currentProgram, option);
			choicesForOption = new String[0]; // TODO: above call is deprecated and equates to this.  Fix me.

			if (choicesForOption.length > 0) {
				printStr.append("[ Possible values = { ");

				for (String choice : choicesForOption) {
					printStr.append(" " + choice + " ");
				}
				printStr.append("} ]");
			}

			defaultVal = optionDefaults.get(option);

			if (defaultVal.length() > 0) {
				printStr.append(" [ Default value = " + optionDefaults.get(option) + " ]");
			}

			printStr.append(" [ Current value = " + options.get(option) + " ]");
			println(printStr.toString());
			println("");
		}
	}

	private void setSomeOptions() {

		Map<String, String> optionsToSet = new HashMap<String, String>();

		optionsToSet.put("PDB.Symbol Repository Path", "/tmp/symbols");
		optionsToSet.put("ASCII Strings.Minimum string length", "LEN_10");
		optionsToSet.put("Decompiler Parameter ID.Prototype Evaluation", "__thiscall");
		optionsToSet.put("Decompiler Parameter ID", "true");
		optionsToSet.put("Decompiler Parameter ID.Analysis Decompiler Timeout (sec)", "90");

		// Set some options by passing in a Map of options to set
		setAnalysisOptions(currentProgram, optionsToSet);

		// Set one specific option individually (pass in option name and value) 
		setAnalysisOption(currentProgram, "Stack", "false");
	}
}
