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
//  
// Reports some basic information about how the binary was disassembled.  If running in 
// headless mode it also generates the signature file.
//
//@category Examples

import ghidra.app.script.GhidraScript;

public class TurnOffStackAnalysis extends GhidraScript {

	public void run() throws Exception {

		setAnalysisOption(currentProgram, "Stack", "false");
		setAnalysisOption(currentProgram, "Function ID", "false");
		/*if(currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString().equals("windows")){
			setAnalysisOption(currentProgram, "Find and Create ASCII Strings", "true");
		}*/
	}
}
