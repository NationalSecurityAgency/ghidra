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

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.*;

import java.util.ArrayList;

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;

/**
 * The RTTI2 data type represents an array of either pointers or displacements to the 
 * BaseClassDescriptors (RTTI 1s) for a class.
 * <p>
 * Fields for this RunTimeTypeInformation structure can be found on http://www.openrce.org
 * <p>
 * RTTI_Base_Class_Array is the label for the RTTI2 data structure.
 *
 * @deprecated Use of this dynamic data type class is no longer recommended. Instead an 
 * array of either pointers or displacements to BaseClassDescriptor structures can be 
 * obtained using the Rtti2Model.
 */
@Deprecated
public class RTTI2DataType extends RTTIDataType {

	private static final int ENTRY_SIZE = 4;
	private final static long serialVersionUID = 1;
	private RTTI1DataType rtti1;
	private long rtti1Count;

	/**
	 * Creates a dynamic Base Class Array data type.
	 */
	public RTTI2DataType() {
		this(null);
	}

	/**
	 * Creates a dynamic Base Class Array data type.
	 * 
	 * @param rtti1Count the number of rtti1 refs
	 */
	public RTTI2DataType(long rtti1Count) {
		this(rtti1Count, null);
	}

	/**
	 * Creates a dynamic Base Class Array data type.
	 * 
	 * @param dtm the data type manager for this data type.
	 */
	public RTTI2DataType(DataTypeManager dtm) {
		super("RTTI_2", dtm);
		rtti1 = new RTTI1DataType(dtm);
	}

	/**
	 * Creates a dynamic Base Class Array data type.
	 * 
	 * @param rtti1Count the number of rtti1 refs
	 * @param dtm the data type manager for this data type.
	 */
	public RTTI2DataType(long rtti1Count, DataTypeManager dtm) {
		super("RTTI_2", dtm);
		this.rtti1Count = rtti1Count;
		rtti1 = new RTTI1DataType(dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new RTTI2DataType(rtti1Count, dtm);
	}

	@Override
	public String getDescription() {
		return "RTTI 2 (RTTI Base Class Array) Structure.";
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "RTTI_2";
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return null;
	}

	private boolean validRefData(Memory memory, Address addr) {
		Program program = memory.getProgram();
		boolean is64Bit = is64Bit(program);
		DataType refDt = getReferenceDataType(program, null);
		DumbMemBufferImpl refBuffer = new DumbMemBufferImpl(memory, addr);
		Settings settings = getReferenceDataType(program, null).getDefaultSettings();
		Object value = refDt.getValue(refBuffer, settings, 4);
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

	@Override
	protected DataTypeComponent[] getAllComponents(MemBuffer buf) {
		ArrayList<DataTypeComponent> list = new ArrayList<>();
		Memory memory = buf.getMemory();
		Address addr = buf.getAddress();
		Program program = memory.getProgram();
		DataTypeManager dtm = program.getDataTypeManager();
		DataType rtti1Dt = new RTTI1DataType(dtm);
		boolean is64Bit = is64Bit(program);
		DataType rtti1RefDt = getReferenceDataType(program, rtti1Dt);
		for (int ordinal = 0; addr != null && validRefData(memory, addr); ordinal++) {
			DataTypeComponent comp = new ReadOnlyDataTypeComponent(rtti1RefDt, this, 4, ordinal,
				ordinal * 4, null, is64Bit ? "rtti1Displacement" : "rtti1Pointer");
			list.add(comp);
			addr = addr.add(4); // Add the data type size.
		}
		return list.toArray(new DataTypeComponent[list.size()]);
	}

	/**
	 * Gets the total length of the data created when this data type is placed at the indicated 
	 * address in memory.
	 * @param memory the program memory for this data.
	 * @param address the start address of the data.
	 * @param bytes the bytes for this data.
	 * @return the length of the data. zero is returned if valid data can't be created at the 
	 * indicated address using this data type.
	 */
	public int getLength(Memory memory, Address address, byte[] bytes) {
		// RTTI2 should start on a 4 byte boundary.
		if (address.getOffset() % 4 != 0) {
			return 0;
		}

		int length = 0;
		Address currentAddress = address;
		while (length + 4 < bytes.length && currentAddress != null &&
			validRefData(memory, currentAddress)) {
			currentAddress = currentAddress.add(4); // Add the data type size.
		}
		return length;
	}

	/**
	 * Gets address referred to by the RTTI 1 pointer at the specified index in the RTTI2's 
	 * array that is at the rtti2Address.
	 * @param memory the program memory containing the RTTI 2
	 * @param rtti2Address the address of the RTTI 2
	 * @param rtti1Index the index of RTTI 1 entry in the RTTI 2 array
	 * @return the address of the RTTI 1 referred to by the indexed array element.
	 */
	public Address getRtti1Address(Memory memory, Address rtti2Address, int rtti1Index) {
		return getRtti1Address(memory.getProgram(), rtti2Address, rtti1Index);
	}

	/**
	 * Gets address referred to by the RTTI 1 pointer at the specified index in the RTTI2's 
	 * array that is at the rtti2Address.
	 * @param program the program containing the RTTI 2
	 * @param rtti2Address the address of the RTTI 2
	 * @param rtti1Index the index of RTTI 1 entry in the RTTI 2 array
	 * @return the address of the RTTI 1 referred to by the indexed array element.
	 */
	public Address getRtti1Address(Program program, Address rtti2Address, int rtti1Index) {
		Address rtti1Address = rtti2Address.add(rtti1Index * 4);
		return getReferencedAddress(program, rtti1Address);
	}

	/**
	 * Determines if the RTTI 1 pointer in the RTTI2 structure is valid.
	 * @param program the program
	 * @param startAddress the address of the RTTI 2 structure
	 * @param pointerIndex index of the element in the array that makes up the RTTI 2.
	 * @param overwriteInstructions true indicates that existing instructions can be overwritten 
	 * by this data type.
	 * @param overwriteDefinedData true indicates that existing defined data can be overwritten 
	 * by this data type.
	 * @return true if the indicated RTTI1 pointer is valid.
	 */
	public boolean isValidRtti1Pointer(Program program, Address startAddress, int pointerIndex,
			boolean overwriteInstructions, boolean overwriteDefinedData) {
		return isValidRtti1Pointer(program, startAddress, pointerIndex,
			convertValidationOptions(overwriteInstructions, overwriteDefinedData));
	}

	/**
	 * Determines if the RTTI 1 pointer in the RTTI2 structure is valid.
	 * @param program the program
	 * @param startAddress the address of the RTTI 2 structure
	 * @param pointerIndex index of the element in the array that makes up the RTTI 2.
	 * @param validationOptions options indicating how to perform the validation
	 * @return true if the indicated RTTI1 pointer is valid.
	 */
	public boolean isValidRtti1Pointer(Program program, Address startAddress, int pointerIndex,
			DataValidationOptions validationOptions) {
		Address pointerAddress = startAddress.add(4 * pointerIndex);
		return isValid(program, pointerAddress, validationOptions);
	}

	@Override
	public boolean isValid(Program program, Address startAddress,
			DataValidationOptions validationOptions) {

		Memory memory = program.getMemory();
		Listing listing = program.getListing();

		if (!memory.contains(startAddress)) {
			return false;
		}

		// Each entry is a 4 byte value.
		long numEntries = (rtti1Count != 0) ? rtti1Count
				: getNumEntries(program, startAddress, validationOptions);
		if (numEntries == 0) {
			return false;
		}
		long length = numEntries * ENTRY_SIZE;
		Address endAddress = startAddress.add(length - 1);
		if (!validRefData(memory, startAddress)) {
			return false;
		}

		if (!validationOptions.shouldIgnoreInstructions() &&
			containsInstruction(listing, startAddress, endAddress)) {
			return false;
		}

		if (!validationOptions.shouldIgnoreDefinedData() &&
			containsDefinedData(listing, startAddress, endAddress)) {
			return false;
		}

		boolean validateReferredToData = validationOptions.shouldValidateReferredToData();

		Address addr = startAddress;
		for (int ordinal = 0; ordinal < numEntries && addr != null &&
			validRefData(memory, addr); ordinal++) {

			// Each component is either a direct reference or an image base offset.
			Address rtti1Address = getReferencedAddress(program, addr);
			if (rtti1Address == null || (validateReferredToData &&
				!rtti1.isValid(program, rtti1Address, validationOptions))) {
				return false;
			}

			try {
				addr = addr.add(ENTRY_SIZE); // Add the data type size.
			}
			catch (AddressOutOfBoundsException e) {
				if (ordinal < (rtti1Count - 1)) {
					return false; // Didn't get all the entries.
				}
				break;
			}
		}

		return true;
	}

	private long getNumEntries(Program program, Address startAddress,
			DataValidationOptions validationOptions) {

		Memory memory = program.getMemory();
		Address addr = startAddress;
		int ordinal = 0;
		for (; addr != null && validRefData(memory, addr); ordinal++) {

			// Each component is either a direct reference or an image base offset.
			Address rtti1Address = getReferencedAddress(program, addr);
			if (rtti1Address == null || !rtti1.isValid(program, rtti1Address, validationOptions)) {
				return ordinal;
			}

			try {
				addr = addr.add(ENTRY_SIZE); // Add the data type size.
			}
			catch (AddressOutOfBoundsException e) {
				return ordinal + 1; // Ordinal hasn't been incremented yet.
			}
		}

		return ordinal;
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "RTTI_2";
	}
}
