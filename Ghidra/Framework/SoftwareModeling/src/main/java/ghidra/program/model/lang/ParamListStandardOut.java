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

import ghidra.program.model.data.*;
import ghidra.program.model.lang.protorules.AssignAction;

/**
 * A list of resources describing possible storage locations for a function's return value,
 * and a strategy for selecting a storage location based on data-types in a function signature.
 *
 * Similar to the parent class, when assigning storage, the first entry that matches the data-type
 * is chosen.  But if this instance fails to find a match (because the return value data-type is too
 * big) the data-type is converted to a pointer and storage is assigned based on that pointer.
 * Additionally, if configured, this instance will signal that a hidden input parameter is required
 * to fully model where the large return value is stored.
 *
 * The resource list is checked to ensure entries are distinguishable.
 */
public class ParamListStandardOut extends ParamListStandard {

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
		int responseCode = assignAddress(proto.outtype, proto, -1, dtManager, status, store);
		if (responseCode == AssignAction.FAIL) {
			// Invoke default hidden return input assignment action
			responseCode = AssignAction.HIDDENRET_PTRPARAM;
		}
		if (responseCode == AssignAction.HIDDENRET_PTRPARAM ||
			responseCode == AssignAction.HIDDENRET_SPECIALREG ||
			responseCode == AssignAction.HIDDENRET_SPECIALREG_VOID) {
			// If the storage is not assigned (because the datatype is too big) create a hidden input parameter
			int sz = proto.model.getPointerSize(spacebase);
			DataType pointerType = dtManager.getPointer(proto.outtype, sz);
			if (responseCode == AssignAction.HIDDENRET_SPECIALREG_VOID) {
				store.type = VoidDataType.dataType;
			}
			else {
				assignAddressFallback(StorageClass.PTR, pointerType, false, status, store);
				store.type = pointerType;
			}
			store.isIndirect = true;	// Signal that there is a hidden return
			if (addAutoParams) {
				ParameterPieces hiddenRet = new ParameterPieces();
				hiddenRet.type = pointerType;
				// Encode whether or not hidden return should be drawn from TYPECLASS_HIDDENRET
				hiddenRet.hiddenReturnPtr = (responseCode == AssignAction.HIDDENRET_SPECIALREG) ||
					(responseCode == AssignAction.HIDDENRET_SPECIALREG_VOID);
				res.add(hiddenRet);	// will get replaced during input storage assignments
			}
		}
	}
}
