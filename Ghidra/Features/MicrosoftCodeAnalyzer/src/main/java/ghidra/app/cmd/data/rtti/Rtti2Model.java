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

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getReferencedAddress;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.util.datatype.microsoft.MSDataTypeUtils;
import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.Memory;

/**
 * Model for run-time type information about the RTTI 2 data type, which represents an 
 * array of either pointers or displacements to the BaseClassDescriptors (RTTI 1s) for 
 * a class.
 * <p>
 * Fields for this RunTimeTypeInformation structure can be found on http://www.openrce.org
 * <p>
 * RTTI_Base_Class_Array is the label for the RTTI2 data structure.
 */
public class Rtti2Model extends AbstractCreateRttiDataModel {

	public static final String DATA_TYPE_NAME = "RTTIBaseClassArray";

	private DataType dataType;
	private DataType simpleIndividualEntryDataType;
	private int entrySize;
	private List<Rtti1Model> rtti1Models;

	/**
	 * Creates the model for the RTTI2 data type.
	 * @param program the program
	 * @param rtti1Count the number of RTTI1 data type references expected at the RTTI2 address.
	 * @param rtti2Address the address in the program for the RTTI Base Class Array.
	 * @param validationOptions options indicating how to validate the data type at the indicated 
	 * address.
	 */
	public Rtti2Model(Program program, int rtti1Count, Address rtti2Address,
			DataValidationOptions validationOptions) {
		super(program, rtti1Count, rtti2Address, validationOptions);
		simpleIndividualEntryDataType = getSimpleIndividualEntryDataType(program);
		entrySize = simpleIndividualEntryDataType.getLength();
		rtti1Models = new ArrayList<>();
	}

	@Override
	public String getName() {
		return DATA_TYPE_NAME;
	}

	@Override
	protected void validateModelSpecificInfo() throws InvalidDataTypeException {

		Program program = getProgram();
		Address startAddress = getAddress();
		long numEntries = getCount();

		Memory memory = program.getMemory();

		// Each entry is a 4 byte value.
		if (numEntries == 0) {
			numEntries = getNumEntries(program, startAddress);
		}
		if (numEntries == 0 || !validRefData(memory, startAddress)) {
			invalid();
		}

		boolean validateReferredToData = validationOptions.shouldValidateReferredToData();

		validateAllRtti1RefEntries(program, startAddress, numEntries, validateReferredToData);
	}

	private void validateAllRtti1RefEntries(Program program, Address startAddress, long numEntries,
			boolean validateReferredToData) throws InvalidDataTypeException {

		Memory memory = program.getMemory();
		Address addr = startAddress;
		for (int ordinal = 0; ordinal < numEntries && addr != null &&
			validRefData(memory, addr); ordinal++) {

			validateRtti1ReferenceEntry(program, validateReferredToData, addr);

			try {
				addr = addr.add(entrySize); // Add the data type size.
			}
			catch (AddressOutOfBoundsException e) {
				if (ordinal < (numEntries - 1)) {
					invalid();
				}
				break;
			}
		}
	}

	private void validateRtti1ReferenceEntry(Program program, boolean validateReferredToData,
			Address addr) throws InvalidDataTypeException {

		// Each component is either a direct reference or an image base offset.
		Address rtti1Address = getReferencedAddress(program, addr);
		if (rtti1Address == null) {
			invalid();
		}
		Rtti1Model rtti1Model = new Rtti1Model(program, rtti1Address, validationOptions);
		rtti1Models.add(rtti1Model);
		if (validateReferredToData) {
			rtti1Model.validate();
		}
		else if (!rtti1Model.isLoadedAndInitializedAddress()) {
			rtti1Models.clear();
			invalid("Data referencing " + Rtti1Model.DATA_TYPE_NAME +
				" data type isn't a loaded and initialized address " + rtti1Address + ".");
		}
	}

	/**
	 * This gets the data type for an individual entry in the array of RTTI 1 references
	 * produced by this model.
	 * @param program the program which will contain this data type. 
	 * @param rtti1Dt the RTTI 1 data type associated with this RTTI 2.
	 * @return the data type for an individual array entry.
	 */
	public static DataType getIndividualEntryDataType(Program program, DataType rtti1Dt) {

		DataTypeManager dataTypeManager = program.getDataTypeManager();

		if (MSDataTypeUtils.is64Bit(program)) {
			return new ImageBaseOffset32DataType(dataTypeManager);
		}

		return new PointerDataType(rtti1Dt, dataTypeManager);
	}

	/**
	 * This gets the data type for an individual entry in the array of RTTI 1 references
	 * produced by this model.
	 * @param program the program which will contain this data type. 
	 * @return the data type for an individual array entry.
	 */
	static DataType getSimpleIndividualEntryDataType(Program program) {

		DataTypeManager dataTypeManager = program.getDataTypeManager();

		if (MSDataTypeUtils.is64Bit(program)) {
			return new ImageBaseOffset32DataType(dataTypeManager);
		}

		return new PointerDataType(dataTypeManager);
	}

	/**
	 * This gets the BaseClassArray (RTTI 2) structure for the indicated program.
	 * @param program the program which will contain this data type. 
	 * @return the BaseClassArray (RTTI 2) structure or null.
	 */
	public DataType getDataType(Program program) {
		DataType rtti1Dt = Rtti1Model.getDataType(program);
		return getDataType(program, rtti1Dt);
	}

	private DataType getDataType(Program program, DataType rtti1Dt) {

		setIsDataTypeAlreadyBasedOnCount(true);
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		int numElements = getCount();
		// Each entry is a 4 byte value.
		if (numElements == 0) {
			numElements = getNumEntries(program, getAddress());
		}
		if (numElements <= 0) {
			return null; // invalid for rtti 2.
		}
		DataType individualEntryDataType = getIndividualEntryDataType(program, rtti1Dt);
		ArrayDataType array = new ArrayDataType(individualEntryDataType, numElements,
			rtti1Dt.getLength(), dataTypeManager);

		return MSDataTypeUtils.getMatchingDataType(program, array);
	}

	/**
	 * This gets the BaseClassArray (RTTI 2) structure for this model.
	 * @return the BaseClassArray (RTTI 2) structure.
	 */
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

	@Override
	public boolean refersToRtti0(Address rtti0Address) {

		try {
			checkValidity();
		}
		catch (InvalidDataTypeException e) {
			return false;
		}

		Program program = getProgram();
		long rtti1Count = getCount();
		Address rtti2Address = getAddress();

		long numEntries = (rtti1Count != 0) ? rtti1Count : getNumEntries(program, rtti2Address);
		if (numEntries == 0) {
			return false;
		}
		if (validationOptions.shouldValidateReferredToData()) {
			for (Rtti1Model rtti1Model : rtti1Models) {
				if (rtti1Model.refersToRtti0(rtti0Address)) {
					return true;
				}
			}
			return false;
		}

		Address addr = rtti2Address;
		Memory memory = program.getMemory();
		for (int ordinal = 0; ordinal < numEntries && addr != null &&
			validRefData(memory, addr); ordinal++) {

			// Each component is either a direct reference or an image base offset.
			Address rtti1Address = getReferencedAddress(program, addr);
			if (rtti1Address == null) {
				return false;
			}
			Rtti1Model rtti1Model = new Rtti1Model(program, rtti1Address, validationOptions);
			if (rtti1Model.refersToRtti0(rtti0Address)) {
				return true;
			}

			addr = addr.add(4); // Add the data type size.
		}
		return false;
	}

	private int getNumEntries(Program program, Address rtti2Address) {

		Memory memory = program.getMemory();
		Address addr = rtti2Address;
		boolean shouldValidateReferredToData = validationOptions.shouldValidateReferredToData();
		int ordinal = 0;
		for (; addr != null && validRefData(memory, addr); ordinal++) {

			// Each component is either a direct reference or an image base offset.
			Address rtti1Address = getReferencedAddress(program, addr);
			if (rtti1Address == null) {
				return ordinal; // It has reached the end.
			}
			Rtti1Model rtti1Model = new Rtti1Model(program, rtti1Address, validationOptions);
			if (shouldValidateReferredToData) {
				try {
					rtti1Model.validate();
				}
				catch (InvalidDataTypeException e1) {
					return ordinal; // It has reached the end.
				}
			}
			else if (!rtti1Model.isLoadedAndInitializedAddress()) {
				return ordinal;
			}

			try {
				addr = addr.add(entrySize); // Add the data type size.
			}
			catch (AddressOutOfBoundsException e) {
				return ordinal + 1; // Ordinal hasn't been incremented yet.
			}
		}

		return ordinal;
	}

	private boolean validRefData(Memory memory, Address addr) {
		Program program = memory.getProgram();
		boolean is64Bit = MSDataTypeUtils.is64Bit(program);
		DumbMemBufferImpl refBuffer = new DumbMemBufferImpl(memory, addr);
		Settings settings = simpleIndividualEntryDataType.getDefaultSettings();
		Object value = simpleIndividualEntryDataType.getValue(refBuffer, settings, 4);
		if (value instanceof Address) {
			Address address = (Address) value;
			if (is64Bit && program.getImageBase().equals(address)) {
				return false; // zero value.
			}
			if (!is64Bit && address.getOffset() == 0L) {
				return false; // zero value.
			}
			return memory.getLoadedAndInitializedAddressSet().contains(address);
		}
		return false;
	}

	/**
	 * Get the Base Class Types (type descriptor names) for the RTTI for this model.
	 * @return the class names or an empty list if the name(s) can't be determined.
	 * @throws InvalidDataTypeException if an invalid model is encountered when trying to get
	 * the base class types. The exception has a message indicating
	 * why it does not appear to be a valid location for the data type.
	 */
	public List<String> getBaseClassTypes() throws InvalidDataTypeException {

		List<String> names = new ArrayList<>();
		Program program = getProgram();
		long rtti1Count = getCount();
		for (int rtti1Index = 0; rtti1Index < rtti1Count; rtti1Index++) {
			Address rtti1Address = getRtti1Address(rtti1Index);

			Rtti1Model rtti1Model = new Rtti1Model(program, rtti1Address, validationOptions);
			if (validationOptions != null) {
				try {
					rtti1Model.validate();
				}
				catch (Exception e) {
					invalid("Not a valid " + Rtti1Model.DATA_TYPE_NAME + " @" + rtti1Address);
				}
			}
			TypeDescriptorModel rtti0ModelForRtti1 = rtti1Model.getRtti0Model();
			String structName = rtti0ModelForRtti1.getDescriptorName();
			if (structName == null) {
				return new ArrayList<>(); // If a name can't be determined return an empty list.
			}
			names.add(structName);
		}
		return names;
	}

	/**
	 * Gets address referred to by the RTTI 1 pointer at the specified index in the RTTI2's array
	 * @param rtti1Index index of the RTTI 1 pointer in the array
	 * @return the address of the RTTI 1.
	 * @throws InvalidDataTypeException if this isn't a valid model at the specified address.
	 */
	public Address getRtti1Address(int rtti1Index) throws InvalidDataTypeException {
		checkValidity();
		Address rtti1Address = getAddress().add(rtti1Index * entrySize);
		return getReferencedAddress(getProgram(), rtti1Address);
	}

	/**
	 * Gets the type descriptor (RTTI 0) model associated with this RTTI 2.
	 * @return the type descriptor (RTTI 0) model or null.
	 * @throws InvalidDataTypeException if this model's validation fails.
	 */
	public TypeDescriptorModel getRtti0Model() throws InvalidDataTypeException {
		checkValidity();
		// If valid, we will have the RTTI1 models already.
		if (!rtti1Models.isEmpty()) {
			// The first RTTI 1 indicates the class for this RTTI 2.
			Rtti1Model rtti1Model = rtti1Models.get(0);
			return rtti1Model.getRtti0Model();
		}
		throw new InvalidDataTypeException(
			getDefaultInvalidMessage() + " The array needs at least one entry.");
	}

	/**
	 * Gets the BaseClassDescriptor (RTTI 1) model associated with this RTTI 2.
	 * @param rtti1Index index of the RTTI 1 pointer in the array
	 * @return the BaseClassDescriptor (RTTI 1) model or null.
	 * @throws InvalidDataTypeException if this model's validation fails.
	 */
	public Rtti1Model getRtti1Model(int rtti1Index) throws InvalidDataTypeException {
		checkValidity();
		return rtti1Models.get(rtti1Index);
	}

}
