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
// Turns off function start searching (intended for use with the 
// headless analyzer as a prescript)
//@category machineLearning

import ghidra.app.script.GhidraScript;

public class TurnOffFuncStartSearch extends GhidraScript {

	@Override
	protected void run() throws Exception {
		setAnalysisOption(currentProgram, "Function Start Search", "false");
		setAnalysisOption(currentProgram, "Function Start Search After Code", "false");
		setAnalysisOption(currentProgram, "Function Start Search After Data", "false");
		setAnalysisOption(currentProgram, "Function ID", "false");

	}

}
