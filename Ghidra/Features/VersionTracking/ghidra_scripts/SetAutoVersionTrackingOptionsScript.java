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
// Example script to set AutoVersionTrackcing options to be used when running AutoVersionTracking
// script in headless mode. Users should copy and rename this script and update the given default
// option values to ones they prefer.
//@category Examples.Version Tracking
import ghidra.app.script.GhidraScript;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.features.base.values.GhidraValuesMap;

public class SetAutoVersionTrackingOptionsScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		GhidraValuesMap optionsMap = getOptions();
		state.addEnvironmentVar("autoVTOptionsMap", optionsMap);
	}

	private GhidraValuesMap getOptions() {

		GhidraValuesMap optionsValues = new GhidraValuesMap();

		// If true, this option will cause the Auto Version Tracker to create implied matches for any
		// applied function matches by other correlators
		optionsValues.defineBoolean(VTOptionDefines.CREATE_IMPLIED_MATCHES_OPTION_TEXT, true);

		// If true, this option will cause Auto Version Tracker to run the Exact Symbol Correlator
		optionsValues.defineBoolean(VTOptionDefines.RUN_EXACT_SYMBOL_OPTION_TEXT, true);

		// If true, this option will cause Auto Version Tracker to run the Exact Data Correlator
		optionsValues.defineBoolean(VTOptionDefines.RUN_EXACT_DATA_OPTION_TEXT, true);

		// If true, this option will cause Auto Version Tracker to run the Exact Function Bytes 
		// Correlator
		optionsValues.defineBoolean(VTOptionDefines.RUN_EXACT_FUNCTION_BYTES_OPTION_TEXT, true);

		// If true, this option will cause Auto Version Tracker to run the Exact Function 
		// Instruction Correlator and the Exact Function Mnemonics Correlator
		optionsValues.defineBoolean(VTOptionDefines.RUN_EXACT_FUNCTION_INST_OPTION_TEXT, true);

		// If true, this option will cause Auto Version Tracker to run the Duplicate Function
		// Correlator
		optionsValues.defineBoolean(VTOptionDefines.RUN_DUPE_FUNCTION_OPTION_TEXT, true);

		// If true, this option will cause Auto Version Tracker to run either the Data Reference 
		// Correlator (if only applied Data matches exist), the Function Reference Correlator 
		// (if only applied Function matches exist), or the Function and Data Reference Correlator 
		// (if both applied data and function matches exist)
		optionsValues.defineBoolean(VTOptionDefines.RUN_REF_CORRELATORS_OPTION_TEXT, true);

		// This option defines the minimum data length for the Exact Data Correlator
		optionsValues.defineInt(VTOptionDefines.DATA_CORRELATOR_MIN_LEN_OPTION_TEXT, 5);

		// This option defines the minimum symbol name lenght for the Exact Symbol Correlator
		optionsValues.defineInt(VTOptionDefines.SYMBOL_CORRELATOR_MIN_LEN_OPTION_TEXT, 3);

		// This option defines the minimum function length for the Exact Function Bytes Correlator, 
		// the Exact Function Instruction Correlator, and the Exact Function Mnemonics Correlator
		optionsValues.defineInt(VTOptionDefines.FUNCTION_CORRELATOR_MIN_LEN_OPTION_TEXT, 10);

		// This option defines the minimum function length for the Duplicate Function Correlator
		// NOTE: This correlator can be slow on programs with large sets of duplicate function 
		// matches so adjusting the length can potentially speed it up
		optionsValues.defineInt(VTOptionDefines.DUPE_FUNCTION_CORRELATOR_MIN_LEN_OPTION_TEXT, 10);

		// If true, this option will cause Implied Matches to be applied according to the limits set
		// for minimum votes and maximum conflicts
		optionsValues.defineBoolean(VTOptionDefines.APPLY_IMPLIED_MATCHES_OPTION_TEXT, true);

		// This option defines the minimum number of votes needed to cause an implied match to be
		// applied
		optionsValues.defineInt(VTOptionDefines.MIN_VOTES_OPTION_TEXT, 2);

		// This option defines the maximum number of conflicts allowed to cause an implied match to 
		// be applied
		optionsValues.defineInt(VTOptionDefines.MAX_CONFLICTS_OPTION_TEXT, 0);

		// This option defines the minimum score needed to apply reference correlator matches
		optionsValues.defineDouble(VTOptionDefines.REF_CORRELATOR_MIN_SCORE_OPTION_TEXT, 0.95);

		// This option defines the minimum confidence level needed to apply reference correlator 
		// matches. Note: Due to the log10 scaling of the confidence the confidence thresholds 
		// equal log 10 (10*optionValue) So optionValue 1.0 = threshold 1.0, optionValue 10.0 
		// = threshold 2.0, optionValue 100 = threshold 3.0
		//	optionsValues.defineDouble(VTOptionDefines.REF_CORRELATOR_MIN_CONF_OPTION_TEXT, 10.0);
		optionsValues.defineDouble(VTOptionDefines.REF_CORRELATOR_MIN_CONF_OPTION_TEXT, 10.0);

		return optionsValues;

	}
}
