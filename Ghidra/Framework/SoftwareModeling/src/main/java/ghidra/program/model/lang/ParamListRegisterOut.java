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

import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.VoidDataType;

/**
 * A list of resources describing possible storage locations for a function's return value,
 * and a strategy for selecting a storage location based on data-types in a function signature.
 * 
 * The assignment strategy for this class is to take the first storage location in the list
 * that fits for the given function signature's return data-type.
 */
public class ParamListRegisterOut extends ParamListStandardOut {

	@Override
	public void assignMap(PrototypePieces proto, DataTypeManager dtManager,
			ArrayList<ParameterPieces> res, boolean addAutoParams) {
		int[] status = new int[numgroup];
		for (int i = 0; i < numgroup; ++i) {
			status[i] = 0;
		}
		ParameterPieces store = new ParameterPieces();
		res.add(store);
		if (VoidDataType.isVoidDataType(proto.outtype)) {
			store.type = proto.outtype;
			return;		// Don't assign storage for VOID
		}
		assignAddress(proto.outtype, proto, -1, dtManager, status, store);
	}

}
