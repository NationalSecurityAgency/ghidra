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
package ghidra.app.util.datatype.microsoft;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DynamicDataType;
import ghidra.program.model.listing.*;

/**
 * An abstract class that each RTTI data type should extend to get common functionality.
 */
public abstract class RTTIDataType extends DynamicDataType {

	/**
	 * Creates an RTTI data type.
	 * @param name the name of the data type.
	 * @param dtm the data type manager for this data type.
	 */
	protected RTTIDataType(String name, DataTypeManager dtm) {
		super(name, dtm);
	}

	/**
	 * Determines if the data type is valid for placing at the indicated address in the program.
	 * @param program the program
	 * @param startAddress the start address
	 * @param overwriteInstructions true indicates that existing instructions can be overwritten 
	 * by this data type.
	 * @param overwriteDefinedData true indicates that existing defined data can be overwritten 
	 * by this data type.
	 * @return true if this data type can be laid down at the specified address.
	 * @see #isValid(Program program, Address address, DataValidationOptions validationOptions)
	 */
	@Deprecated
	public boolean isValid(Program program, Address startAddress, boolean overwriteInstructions,
			boolean overwriteDefinedData) {

		return isValid(program, startAddress,
			convertValidationOptions(overwriteInstructions, overwriteDefinedData));
	}

	/**
	 * Creates a DataValidationOptions object with the indicated settings for instructions 
	 * and defined data. Other validation options will be set to the default values.
	 * @param overwriteInstructions true indicates it is valid to overwrite instructions
	 * @param overwriteDefinedData true indicates it is valid to overwrite defined data
	 * @return the DataValidationOptions object
	 */
	protected DataValidationOptions convertValidationOptions(boolean overwriteInstructions,
			boolean overwriteDefinedData) {
		DataValidationOptions validationOptions = new DataValidationOptions();
		validationOptions.setValidateReferredToData(true); // TODO Should this be false?
		validationOptions.setIgnoreInstructions(overwriteInstructions);
		validationOptions.setIgnoreDefinedData(overwriteDefinedData);
		return validationOptions;
	}

	/**
	 * Determines if the data type is valid for placing at the indicated address in the program.
	 * @param program the program
	 * @param address the address where the validated data type will be used to create data
	 * @param validationOptions options indicating how to perform the validation
	 * @return true if this data type can be laid down at the specified address
	 */
	public abstract boolean isValid(Program program, Address address,
			DataValidationOptions validationOptions);

	/**
	 * Determines if data is already defined between the start and end address.
	 * @param listing the program listing where the data type is to be placed.
	 * @param startAddress the start address of the range to check.
	 * @param endAddress the end address of the range to check.
	 * @return true if there is already defined data in the range from the start to end address.
	 */
	boolean containsDefinedData(Listing listing, Address startAddress, Address endAddress) {
		Data data = listing.getDefinedDataAt(startAddress);
		if (data != null) {
			return true;
		}
		data = listing.getDefinedDataAfter(startAddress);
		if (data != null && data.getMinAddress().compareTo(endAddress) <= 0) {
			return true;
		}
		return false;
	}

	/**
	 * Determines if an instruction is already defined between the start and end address.
	 * @param listing the program listing where the data type is to be placed.
	 * @param startAddress the start address of the range to check.
	 * @param endAddress the end address of the range to check.
	 * @return true if there is already an instruction in the range from the start to end address.
	 */
	boolean containsInstruction(Listing listing, Address startAddress, Address endAddress) {
		Instruction instruction = listing.getInstructionAt(startAddress);
		if (instruction != null) {
			return true;
		}
		instruction = listing.getInstructionAfter(startAddress);
		if (instruction != null && instruction.getMinAddress().compareTo(endAddress) <= 0) {
			return true;
		}
		return false;
	}

}
