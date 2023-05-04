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
package ghidra.app.util.bin.format.dwarf4.next;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.*;

/**
 * Logic to test if a Data instance is replaceable with a data type. 
 */
public class DWARFDataInstanceHelper {
	private Program program;
	private Listing listing;

	public DWARFDataInstanceHelper(Program program) {
		this.program = program;
		this.listing = program.getListing();
	}

	private boolean isArrayDataTypeCompatibleWithExistingData(Array arrayDT, Data existingData) {

		DataType existingDataDT = existingData.getBaseDataType();
		if (existingDataDT.isEquivalent(arrayDT)) {
			return true;
		}

		DataType elementDT = arrayDT.getDataType();
		if (elementDT instanceof TypeDef typedef) {
			elementDT = typedef.getBaseDataType();
		}
		
		DataType existingElementDT = existingDataDT instanceof Array existingArrayDT 
				? existingArrayDT.getDataType() 
				: null;
		if (elementDT instanceof CharDataType && existingDataDT instanceof StringDataType) {
			// hack to allow a char array to overwrite a string in memory
			existingElementDT = elementDT;
		}
		if (existingElementDT instanceof TypeDef typedef) {
			existingElementDT = typedef.getBaseDataType();
		}
		
		if (existingDataDT instanceof Array || existingDataDT instanceof StringDataType) {
			if (!existingElementDT.isEquivalent(elementDT)) {
				return false;
			}

			if (arrayDT.getLength() <= existingData.getLength()) {
				// if proposed array is smaller than in-memory array: ok
				return true;
			}

			// if proposed array is longer than in-memory array, check if there is only 
			// undefined data following the in-memory array
			return hasTrailingUndefined(existingData, arrayDT);
		}

		// existing data wasn't an array, test each location the proposed array would overwrite
		Address address = existingData.getAddress();
		for (int i = 0; i < arrayDT.getNumElements(); i++) {
			Address elementAddress = address.add(arrayDT.getElementLength() * i);
			Data data = listing.getDataAt(elementAddress);
			if (data != null && !isDataTypeCompatibleWithExistingData(elementDT, data)) {
				return false;
			}
		}

		return true;
	}

	private boolean hasTrailingUndefined(Data data, DataType replacementDT) {
		Address address = data.getAddress();
		return DataUtilities.isUndefinedRange(program, address.add(data.getLength()),
			address.add(replacementDT.getLength() - 1));
	}

	private boolean isStructDataTypeCompatibleWithExistingData(Structure structDT,
			Data existingData) {
		DataType existingDataDT = existingData.getBaseDataType();
		if (existingDataDT instanceof Structure) {
			return existingDataDT.isEquivalent(structDT);
		}

		// existing data wasn't a structure, test each location the proposed structure would overwrite
		Address address = existingData.getAddress();
		for (DataTypeComponent dtc : structDT.getDefinedComponents()) {
			Address memberAddress = address.add(dtc.getOffset());
			Data data = listing.getDataAt(memberAddress);
			if (data != null && !isDataTypeCompatibleWithExistingData(dtc.getDataType(), data)) {
				return false;
			}
		}
		return true;
	}

	private boolean isPointerDataTypeCompatibleWithExistingData(Pointer pdt, Data existingData) {
		DataType existingDT = existingData.getBaseDataType();

		// allow 'upgrading' an integer type to a pointer
		boolean isRightType =
			(existingDT instanceof Pointer) || (existingDT instanceof AbstractIntegerDataType);
		return isRightType && existingDT.getLength() == pdt.getLength();
	}

	private boolean isSimpleDataTypeCompatibleWithExistingData(DataType simpleDT,
			Data existingData) {
		// dataType will only be a base data type, not a typedef

		DataType existingDT = existingData.getBaseDataType();
		if (simpleDT instanceof CharDataType && existingDT instanceof StringDataType) {
			// char overwriting a string
			return true;
		}

		if (!simpleDT.getClass().isInstance(existingDT)) {
			return false;
		}
		int dataTypeLen = simpleDT.getLength();
		if (dataTypeLen > 0 && dataTypeLen != existingData.getLength()) {
			return false;
		}
		return true;
	}

	private boolean isEnumDataTypeCompatibleWithExistingData(Enum enumDT, Data existingData) {
		// This is a very fuzzy check to see if the value located at address is compatible.
		// Match if its an enum or integer with correct size.  The details about enum
		// members are ignored.
		DataType existingDT = existingData.getBaseDataType();
		if (!(existingDT instanceof Enum || existingDT instanceof AbstractIntegerDataType)) {
			return false;
		}
		if (existingDT instanceof BooleanDataType) {
			return false;
		}
		if (existingDT.getLength() != enumDT.getLength()) {
			return false;
		}
		return true;
	}

	private boolean isDataTypeCompatibleWithExistingData(DataType dataType, Data existingData) {
		if (existingData == null || !existingData.isDefined()) {
			return true;
		}

		if (dataType instanceof Array) {
			return isArrayDataTypeCompatibleWithExistingData((Array) dataType, existingData);
		}
		if (dataType instanceof Pointer) {
			return isPointerDataTypeCompatibleWithExistingData((Pointer) dataType, existingData);
		}
		if (dataType instanceof Structure) {
			return isStructDataTypeCompatibleWithExistingData((Structure) dataType, existingData);
		}
		if (dataType instanceof TypeDef) {
			return isDataTypeCompatibleWithExistingData(((TypeDef) dataType).getBaseDataType(),
				existingData);
		}
		if (dataType instanceof Enum) {
			return isEnumDataTypeCompatibleWithExistingData((Enum) dataType, existingData);
		}

		if (dataType instanceof AbstractIntegerDataType ||
			dataType instanceof AbstractFloatDataType || dataType instanceof StringDataType ||
			dataType instanceof WideCharDataType || dataType instanceof WideChar16DataType ||
			dataType instanceof WideChar32DataType) {
			return isSimpleDataTypeCompatibleWithExistingData(dataType, existingData);
		}

		return false;
	}

	public boolean isDataTypeCompatibleWithAddress(DataType dataType, Address address) {
		if (DataUtilities.isUndefinedRange(program, address,
			address.add(dataType.getLength() - 1))) {
			return true;
		}

		Data data = listing.getDataAt(address);
		return data == null || isDataTypeCompatibleWithExistingData(dataType, data);
	}

}
