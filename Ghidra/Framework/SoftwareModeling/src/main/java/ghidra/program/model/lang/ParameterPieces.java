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

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.InvalidInputException;

/**
 * Basic elements of a parameter: address, data-type, properties
 */
public class ParameterPieces {
	public Address address;						// Storage address of the parameter
	public DataType type;						// The data-type of the parameter
	public Varnode[] joinPieces;				// If non-null, multiple pieces stitched together for single logical value
	public boolean isThisPointer = false;		// True if the "this" pointer
	public boolean hiddenReturnPtr = false;		// True if input pointer to return storage
	public boolean isIndirect = false;			// True if parameter is indirect pointer to actual parameter
//	public boolean nameLock;
//	public boolean typeLock;
//	public boolean sizeLock;

	/**
	 * Swap data-type markup between this and another parameter
	 * 
	 * Swap any data-type and flags, but leave the storage address intact.
	 * This assumes the two parameters are the same size.
	 * @param op is the other parameter to swap with this.
	 */
	public void swapMarkup(ParameterPieces op) {
		boolean tmpHidden = hiddenReturnPtr;
		boolean tmpIndirect = isIndirect;
		boolean tmpThis = isThisPointer;
		DataType tmpType = type;
		Varnode[] tmpJoin = joinPieces;
		hiddenReturnPtr = op.hiddenReturnPtr;
		isIndirect = op.isIndirect;
		isThisPointer = op.isThisPointer;
		type = op.type;
		joinPieces = op.joinPieces;
		op.hiddenReturnPtr = tmpHidden;
		op.isIndirect = tmpIndirect;
		op.isThisPointer = tmpThis;
		op.type = tmpType;
		op.joinPieces = tmpJoin;
	}

	public VariableStorage getVariableStorage(Program program) {
		if (type == null) {
			type = DataType.DEFAULT;
		}
		if (VoidDataType.isVoidDataType(type)) {
			if (isIndirect) {
				return DynamicVariableStorage.INDIRECT_VOID_STORAGE;
			}
			return VariableStorage.VOID_STORAGE;
		}
		int sz = type.getLength();
		if (sz == 0) {
			return VariableStorage.UNASSIGNED_STORAGE;
		}
		if (isThisPointer) {
			try {
				if (address != null) {
					return new DynamicVariableStorage(program, AutoParameterType.THIS, address, sz);
				}
			}
			catch (InvalidInputException e) {
				// Fall thru to getUnaassignedDynamicStorage
			}
			return DynamicVariableStorage.getUnassignedDynamicStorage(AutoParameterType.THIS);
		}
		if ((address == null || address == Address.NO_ADDRESS) && joinPieces == null) {
			return DynamicVariableStorage.getUnassignedDynamicStorage(isIndirect);
		}
		VariableStorage store;
		try {
			if (joinPieces != null) {
				store = new DynamicVariableStorage(program, isIndirect, joinPieces);
			}
			else {
				if (hiddenReturnPtr) {
					store = new DynamicVariableStorage(program,
						AutoParameterType.RETURN_STORAGE_PTR, address, sz);
				}
				else {
					store = new DynamicVariableStorage(program, isIndirect, address, sz);
				}
			}
		}
		catch (InvalidInputException e) {
			store = DynamicVariableStorage.getUnassignedDynamicStorage(isIndirect);
		}
		return store;
	}
}
