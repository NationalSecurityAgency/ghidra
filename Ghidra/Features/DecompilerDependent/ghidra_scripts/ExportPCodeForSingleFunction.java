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
//Decompile the function at the cursor and its callees, then output facts files corresponding to the pcodes
//@category PCode

import java.util.HashSet;
import java.util.Set;

import ghidra.program.model.listing.Function;

public class ExportPCodeForSingleFunction extends ExportPCodeForCTADL {

	protected Set<Function> getFunctionSet() {
		Set<Function> toProcess = new HashSet<Function>();
		toProcess.add(getFunctionContaining(currentAddress));
		return toProcess;
	}

}
