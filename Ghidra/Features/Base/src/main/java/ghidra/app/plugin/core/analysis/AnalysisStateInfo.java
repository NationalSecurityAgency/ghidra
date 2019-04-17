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

import java.util.HashMap;

import ghidra.program.model.listing.Program;

/**
 * AnalysisStateInfo holds onto AnalysisState information associated with analysis of a 
 * particular program. An AnalysisState can be associated with an individual analyzer 
 * or a group of analyzers which maintain information common to those analyzers for a 
 * program's analysis. The point of an analysis state is to maintain information between
 * individual invocations of a particular analyzer or between differing analyzers that 
 * have information in common. For example, an instruction type of analyzer is invoked 
 * repeatedly during analysis as various blocks of instructions are created by disassembly. 
 * If you need to maintain a set of addresses that have been processed by the analyzer so 
 * that they aren't unnecessarily reprocessed, you could maintain the address set in an 
 * analysis state. This allows the analysis information to be maintained from one invocation 
 * to the next or from one analyzer to another.
 */
public class AnalysisStateInfo {

	private static HashMap<Program, HashMap<Class<? extends AnalysisState>, AnalysisState>> programStates =
		new HashMap<>();

	private AnalysisStateInfo() {
		// no construct
	}

	/**
	 * Return previously stored <code>AnalysisState</code> of the specified analysisStateClass type 
	 * for the specified program.
	 * @param program
	 * @param analysisStateClass type of <code>AnalysisState</code>
	 * @return analysis state or null if not previously stored via {@link #putAnalysisState(Program, AnalysisState)}
	 */
	@SuppressWarnings("unchecked") // putAnalysisState ensures that stored instance corresponds to key class
	public static <T extends AnalysisState> T getAnalysisState(Program program,
			Class<T> analysisStateClass) {
		HashMap<Class<? extends AnalysisState>, AnalysisState> stateMap =
			programStates.get(program);
		if (stateMap != null) {
			// Found the map for this program.
			return (T) stateMap.get(analysisStateClass);
		}
		return null;
	}

	/**
	 * Store/replace a specific AnalysisState implementation for a specific program.
	 * Note that only a single instance of a given AnaysisState class implementation
	 * will be stored for a given program. 
	 * @param program
	 * @param state analysis state instance
	 */
	public static void putAnalysisState(final Program program, AnalysisState state) {
		HashMap<Class<? extends AnalysisState>, AnalysisState> stateMap =
			programStates.get(program);
		if (stateMap == null) {
			stateMap = new HashMap<>();
			programStates.put(program, stateMap);
			program.addCloseListener(() -> programStates.remove(program));
		}
		stateMap.put(state.getClass(), state);
	}

}
