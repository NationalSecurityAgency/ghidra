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
package ghidra.program.model.lang;

import java.util.ArrayList;

import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;

/**
 * A list of resources describing possible storage locations for a function's return value,
 * and a strategy for selecting a storage location based on data-types in a function signature.
 * 
 * The assignment strategy for this class is to take the first storage location in the list
 * that fits for the given function signature's return data-type.
 */
public class ParamListRegisterOut extends ParamListStandard {

	@Override
	public void assignMap(Program prog, DataType[] proto, ArrayList<VariableStorage> res,
			boolean addAutoParams) {
		int[] status = new int[numgroup];
		for (int i = 0; i < numgroup; ++i) {
			status[i] = 0;
		}
		VariableStorage store = assignAddress(prog, proto[0], status, false, false);
		res.add(store);
	}

}
