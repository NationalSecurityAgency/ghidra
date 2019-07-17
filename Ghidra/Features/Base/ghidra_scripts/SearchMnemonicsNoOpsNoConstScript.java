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
//The script will use the selected instructions and build a combined mask/value buffer.
//Memory is then searched looking for this combined value buffer that represents the selected instructions.
//This automates the process of searching through memory for a particular ordering of instructions by hand.
//@category Search.InstructionPattern

public class SearchMnemonicsNoOpsNoConstScript extends SearchBaseExtended {

	@Override
	public void run() {
		setState(new SLMaskControl(true, false, false, false));
		loadSelectedInstructions();
		executeSearch();
	}

}
