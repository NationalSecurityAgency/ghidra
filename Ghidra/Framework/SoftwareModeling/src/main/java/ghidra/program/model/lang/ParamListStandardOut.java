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

import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.exception.InvalidInputException;

import java.util.ArrayList;

public class ParamListStandardOut extends ParamListStandard {

	@Override
	public void assignMap(Program prog, DataType[] proto, boolean isinput,
			ArrayList<VariableStorage> res, boolean addAutoParams) {

		int[] status = new int[numgroup];
		for (int i = 0; i < numgroup; ++i)
			status[i] = 0;

		VariableStorage store = assignAddress(prog, proto[0], status, false, false);
		if (!store.isUnassignedStorage()) {
			res.add(store);
			return;
		}
		// If the storage is not assigned (because the datatype is too big) create a hidden input parameter
		DataType pointer = prog.getDataTypeManager().getPointer(proto[0]);
		store = assignAddress(prog, pointer, status, false, false);
		try {
			if (store.isValid()) {
				store = new DynamicVariableStorage(prog, true, store.getVarnodes());
				res.add(store);
				// Signal to input assignment that there is a hidden return using additional unassigned storage param
			}
			if (addAutoParams) {
				res.add(VariableStorage.UNASSIGNED_STORAGE); // will get replaced during input storage assignments
			}
		}
		catch (InvalidInputException e) {
			store = VariableStorage.UNASSIGNED_STORAGE;
			res.add(store);
		}

	}

}
