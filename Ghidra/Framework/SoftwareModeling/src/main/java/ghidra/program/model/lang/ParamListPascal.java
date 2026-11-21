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
import ghidra.program.model.lang.protorules.AssignAction;

/**
 * Pascal analysis for parameter lists
 *
 */
public class ParamListPascal extends ParamListStandard {

	@Override
	public void assignMap(PrototypePieces proto, DataTypeManager dtManager, int[] status,
			ArrayList<ParameterPieces> res, boolean addAutoParams) {

		boolean hiddenParam = (addAutoParams && res.size() == 2);
		int paramStart = res.size();
		ParameterPieces hiddenPtr = res.get(res.size() - 1);

		for (int i = proto.intypes.size() - 1; i > 0; --i) { // Don't do i==0, could be a 'this' and may need allocating after 'hiddenPtr'
			ParameterPieces store = new ParameterPieces();
			res.add(paramStart, store);
			int resCode =
				assignAddress(proto.intypes.get(i), proto, i, dtManager, status, store);
			if (resCode == AssignAction.FAIL || resCode == AssignAction.NO_ASSIGNMENT) {
				// Do not continue to assign after first failure
				while (--i >= 0) {
					store = new ParameterPieces();		// Fill out with UNASSIGNED pieces
					res.add(store);
				}
				return;
			}
		}

		if (proto.intypes.size() == 0) {
			allocateHiddenReturn(proto, dtManager, status, hiddenParam, hiddenPtr);
			return;
		}

		int thisOrFirstParamPos = paramStart;
		ParameterPieces store = new ParameterPieces();
		if (proto.model.hasThisPointer()) {
			store.isThisPointer = true; // here, proto.intypes.get(0) is a 'this'
		}
		if (proto.model.getInputResource().isThisBeforeRetPointer()) { // implies 'hasThis'
			if (allocateHiddenReturn(proto, dtManager, status, hiddenParam, hiddenPtr)) {
				--thisOrFirstParamPos;
			}
			assignAddress(proto.intypes.get(0), proto, 0, dtManager, status, store);
		}
		else {
			assignAddress(proto.intypes.get(0), proto, 0, dtManager, status, store);
			allocateHiddenReturn(proto, dtManager, status, hiddenParam, hiddenPtr);
		}
		res.add(thisOrFirstParamPos, store);
	}

	private boolean allocateHiddenReturn(PrototypePieces proto, DataTypeManager dtManager, int[] status,
			boolean hiddenParam, ParameterPieces hiddenPtr) {
		if (hiddenParam) {	// Check for hidden parameters defined by the output list
//			hiddenPtr.hiddenReturnPtr = true;
			if (hiddenPtr.hiddenReturnPtr) {
				// Need to pull from registers marked as hiddenret
				assignAddressFallback(StorageClass.HIDDENRET, hiddenPtr.type, false, status,
					hiddenPtr);
			}
			else {
				// Assign as a regular first input pointer parameter
				assignAddress(hiddenPtr.type, proto, 0, dtManager, status, hiddenPtr);
			}
			hiddenPtr.hiddenReturnPtr = true;
		}
		return hiddenParam;
	}
}
