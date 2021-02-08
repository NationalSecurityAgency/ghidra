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
package ghidra.app.cmd.data.rtti;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.*;

import ghidra.app.cmd.data.AbstractCreateDataTypeModel;
import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.util.datatype.microsoft.MSDataTypeUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

/**
 * Model for vf table information associated with a CompleteObjectLocator (RTTI 4) data type.
 * <p>
 * VF Table
 * <p>
 * Info for the association of this data can be found on http://www.openrce.org
 * <p>
 */
public class VfTableModel extends AbstractCreateDataTypeModel {

	public static final String DATA_TYPE_NAME = "vftable";
	private static final int NO_LAST_COUNT = -1;

	private DataType dataType;
	private Rtti4Model rtti4Model;

	private Program lastProgram;
	private DataType lastDataType;
	private int lastElementCount = NO_LAST_COUNT;
	private int elementCount = 0;

	/**
	 * Creates the model for the vf table data.
	 * @param program the program
	 * @param vfTableAddress the address in the program for the vf table data.
	 * @param validationOptions options indicating how to validate the data type at the indicated 
	 * address.
	 */
	public VfTableModel(Program program, Address vfTableAddress,
			DataValidationOptions validationOptions) {
		// use one for the data type element count, because there is only one array of some element size
		super(program, 1, vfTableAddress,
			validationOptions);
		elementCount= RttiUtil.getVfTableCount(program, vfTableAddress);
	}
	
	/**
	 * Get the number of vftable elements in this vftable
	 * @return number of elements
	 */
	public int getElementCount() {
		return elementCount;
	}

	@Override
	public String getName() {
		return DATA_TYPE_NAME;
	}

	@Override
	public void validateModelSpecificInfo() throws InvalidDataTypeException {

		Program program = getProgram();
		Address startAddress = getAddress();

		// Get the model from the meta pointer.
		Address metaAddress = getMetaAddress();
		Address rtti4Address = getAbsoluteAddress(program, metaAddress);
		rtti4Model = new Rtti4Model(program, rtti4Address, validationOptions);

		// Get the table
		DataType individualEntryDataType = new PointerDataType(program.getDataTypeManager());
		long entrySize = individualEntryDataType.getLength();

		// Each entry is a pointer to where a function can possibly be created.
		long numEntries = elementCount;
		if (numEntries == 0) {
			throw new InvalidDataTypeException(
				getName() + " data type at " + getAddress() + " doesn't have a valid vf table.");
		}

		Address vfTableFieldAddress = startAddress;
		for (int ordinal = 0; ordinal < numEntries && vfTableFieldAddress != null; ordinal++) {

			// Each component is a pointer (to a function).
			Address functionAddress = getAbsoluteAddress(program, vfTableFieldAddress);
			if (functionAddress == null) {
				throw new InvalidDataTypeException(
					getName() + " at " + getAddress() + " doesn't refer to a valid function.");
			}

			try {
				vfTableFieldAddress = vfTableFieldAddress.add(entrySize); // Add the data type size.
			}
			catch (AddressOutOfBoundsException e) {
				if (ordinal < (numEntries - 1)) {
					throw new InvalidDataTypeException(
						getName() + " at " + getAddress() + " isn't valid.");
				}
				break;
			}
		}
	}

	/**
	 * This gets the vf table structure for the indicated program.
	 * @param program the program which will contain this data. 
	 * @return the vf table structure as an array.
	 */
	private DataType getDataType(Program program) {

		if (program != lastProgram || lastElementCount == NO_LAST_COUNT) {
			setIsDataTypeAlreadyBasedOnCount(true);

			lastProgram = program;
			lastDataType = null;
			lastElementCount = elementCount;
			
			if (lastElementCount > 0) {
				DataTypeManager dataTypeManager = program.getDataTypeManager();
				PointerDataType pointerDt = new PointerDataType(dataTypeManager);

				// Create an array of pointers and return it.
				ArrayDataType arrayDataType = new ArrayDataType(pointerDt, lastElementCount,
					pointerDt.getLength(), dataTypeManager);

				lastDataType = MSDataTypeUtils.getMatchingDataType(program, arrayDataType);
			}
			else {
				lastDataType = null;
			}
		}
		return lastDataType;
	}

	@Override
	public DataType getDataType() {
		if (dataType == null) {
			dataType = getDataType(getProgram());
		}
		return dataType;
	}

	@Override
	protected int getDataTypeLength() {
		DataType dt = getDataType();
		return (dt != null) ? dt.getLength() : 0;
	}

	/**
	 * Gets the address of the virtual function pointed to by the vf table element at the index 
	 * specified by <code>tableElementIndex</code>.
	 * @param tableElementIndex index of the vf table element
	 * @return the virtual function's address or null
	 */
	public Address getVirtualFunctionPointer(int tableElementIndex) {
		Address tableAddress = getAddress();
		int defaultPointerSize = getDefaultPointerSize();
		Address address = tableAddress.add(defaultPointerSize * tableElementIndex);
		return getAbsoluteAddress(getProgram(), address);
	}

	/**
	 * Gets the type descriptor (RTTI 0) model associated with this vf table.
	 * @return the type descriptor (RTTI 0) model or null.
	 * @throws InvalidDataTypeException if this model's validation fails.
	 */
	public TypeDescriptorModel getRtti0Model() throws InvalidDataTypeException {
		checkValidity();
		return rtti4Model.getRtti0Model();
	}

	/**
	 * Gets the address of the location containing the meta pointer, which points to the RTTI 4 
	 * associated with this vf table.
	 * @return the address of the meta pointer
	 */
	private Address getMetaAddress() {
		return getAddress().subtract(getProgram().getDefaultPointerSize());
	}
}
