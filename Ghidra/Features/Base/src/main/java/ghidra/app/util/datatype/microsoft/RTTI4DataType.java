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

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;

/**
 * The RTTI4 data type represents a CompleteObjectLocator structure.
 * <p>
 * Fields for this RunTimeTypeInformation structure can be found on http://www.openrce.org
 * <p>
 * <pre>
 * struct CompleteObjectLocator {
 *     dword signature;
 *     dword offset;             // offset of vbtable within class
 *     dword cdOffset;           // constructor displacement offset
 *     4byte_ptr_or_disp pRtti0; // ref to TypeDescriptor (RTTI 0) for class
 *     4byte_ptr_or_disp pRtti3; // ref to ClassHierarchyDescriptor (RTTI 3)
 * }
 * </pre>
 * <p>
 * RTTI_Complete_Object_Locator is the label for the RTTI4 data structure.
 *
 * @deprecated Use of this dynamic data type class is no longer recommended. Instead a
 * CompleteObjectLocator structure data type can be obtained using the Rtti4Model.
 */
@Deprecated
public class RTTI4DataType extends RTTIDataType {

	private final static long serialVersionUID = 1;
	private final static int LENGTH = 20;
	private final static int SIGNATURE_OFFSET = 0;
	private final static int VB_TABLE_OFFSET_OFFSET = 4;
	private final static int CONSTRUCTOR_DISP_OFFSET_OFFSET = 8;
	private final static int RTTI_0_OFFSET = 12;
	private final static int RTTI_3_OFFSET = 16;
	private DataTypeComponent[] fixedComps;
	private RTTI0DataType rtti0;
	private RTTI3DataType rtti3;

	/**
	 * Creates a dynamic Complete Object Locator data type.
	 */
	public RTTI4DataType() {
		this(null);
	}

	/**
	 * Creates a dynamic Complete Object Locator data type.
	 * @param dtm the data type manager for this data type.
	 */
	public RTTI4DataType(DataTypeManager dtm) {
		super("RTTI_4", dtm);
		buildFixedComponents();
		rtti0 = new RTTI0DataType(dtm);
		rtti3 = new RTTI3DataType(dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new RTTI4DataType(dtm);
	}

	private void buildFixedComponents() {
		fixedComps = new DataTypeComponent[3];
		fixedComps[0] = new ReadOnlyDataTypeComponent(new DWordDataType(), this, 4, 0,
			SIGNATURE_OFFSET, "signature", null);
		fixedComps[1] = new ReadOnlyDataTypeComponent(new DWordDataType(), this, 4, 1,
			VB_TABLE_OFFSET_OFFSET, "offset", "offset of vbtable within class");
		fixedComps[2] = new ReadOnlyDataTypeComponent(new DWordDataType(), this, 4, 2,
			CONSTRUCTOR_DISP_OFFSET_OFFSET, "cdOffset", "constructor displacement offset");
	}

	@Override
	public String getDescription() {
		return "RTTI 4 (RTTI Complete Object Locator) Structure";
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "RTTI_4";
	}

	@Override
	public int getLength() {
		return LENGTH;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return null;
	}

	@Override
	protected DataTypeComponent[] getAllComponents(MemBuffer buf) {
		Program program = buf.getMemory().getProgram();
		DataTypeManager dtm = program.getDataTypeManager();
		DataType rtti0Dt = new RTTI0DataType(dtm);
		DataType rtti3Dt = new RTTI3DataType(dtm);
		DataType rtti0RefDt = getReferenceDataType(program, rtti0Dt);
		DataType rtti3RefDt = getReferenceDataType(program, rtti3Dt);

		DataTypeComponent[] comps = new DataTypeComponent[5];
		System.arraycopy(fixedComps, 0, comps, 0, 3);
		comps[3] = new ReadOnlyDataTypeComponent(rtti0RefDt, this, 4, 3, RTTI_0_OFFSET,
			"pTypeDescriptor", is64Bit(program) ? "rtti0Displacement" : "rtti0Pointer");
		comps[4] = new ReadOnlyDataTypeComponent(rtti3RefDt, this, 4, 4, RTTI_3_OFFSET,
			"pClassDescriptor", is64Bit(program) ? "rtti3Displacement" : "rtti3Pointer");
		return comps;
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
		Program program = memory.getProgram();
		// RTTI4 should start on a 4 byte boundary.
		if (address.getOffset() % 4 != 0) {
			return 0;
		}
		// check RTTI4 length in bytes.
		if (bytes.length < LENGTH) {
			return 0;
		}

		// First 12 bytes is 3 dword numeric values.
		// Next there may be bytes to align the rtti0 pointer.

		// Next component should refer to RTTI0.
		Address rtti0CompAddress = address.add(RTTI_0_OFFSET);
		Address rtti0Address = getReferencedAddress(program, rtti0CompAddress);
		if (rtti0Address == null || !memory.contains(rtti0Address)) {
			return 0;
		}

		// Last component should refer to RTTI3.
		Address rtti3CompAddress = address.add(RTTI_3_OFFSET);
		Address rtti3Address = getReferencedAddress(program, rtti3CompAddress);
		if (rtti3Address == null || !memory.contains(rtti3Address)) {
			return 0;
		}

		return LENGTH;
	}

	/**
	 * Gets the address of the RTTI0 that is referred to from an RTTI4 structure that is placed at 
	 * the indicated address.
	 * @param memory the memory with the data for the RTTI structures.
	 * @param rtti4Address address of an RTTI4 structure
	 * @return the address of the RTTI0 structure or null.
	 */
	public Address getRtti0Address(Memory memory, Address rtti4Address) {
		Program program = memory.getProgram();
		Address rtti0CompAddress = rtti4Address.add(RTTI_0_OFFSET);
		return getReferencedAddress(program, rtti0CompAddress);
	}

	/**
	 * Gets the address of the RTTI3 that is referred to from an RTTI4 structure that is placed at 
	 * the indicated address.
	 * @param memory the memory with the data for the RTTI structures.
	 * @param rtti4Address address of an RTTI4 structure
	 * @return the address of the RTTI3 structure or null.
	 */
	public Address getRtti3Address(Memory memory, Address rtti4Address) {
		Program program = memory.getProgram();
		Address rtti3CompAddress = rtti4Address.add(RTTI_3_OFFSET);
		return getReferencedAddress(program, rtti3CompAddress);
	}

	@Override
	public boolean isValid(Program program, Address startAddress,
			DataValidationOptions validationOptions) {

		Memory memory = program.getMemory();
		if (!memory.contains(startAddress)) {
			return false;
		}

		// RTTI4 should start on a 4 byte boundary.
		if (startAddress.getOffset() % 4 != 0) {
			return false;
		}

		Listing listing = program.getListing();
		Address endAddress = startAddress.add(LENGTH - 1);
		try {
			MSDataTypeUtils.getBytes(memory, startAddress, LENGTH);
		}
		catch (InvalidDataTypeException e) {
			return false; // Couldn't get enough bytes from memory for an RTTI4.
		}

		if (!validationOptions.shouldIgnoreInstructions() &&
			containsInstruction(listing, startAddress, endAddress)) {
			return false;
		}

		if (!validationOptions.shouldIgnoreDefinedData() &&
			containsDefinedData(listing, startAddress, endAddress)) {
			return false;
		}

		// First 12 bytes is 3 dword numeric values.

		boolean validateReferredToData = validationOptions.shouldValidateReferredToData();

		// Fourth component should refer to RTTI0.
		Address rtti0CompAddress = startAddress.add(RTTI_0_OFFSET);
		Address rtti0Address = getReferencedAddress(program, rtti0CompAddress);
		if (rtti0Address == null ||
			(validateReferredToData && !rtti0.isValid(program, rtti0Address, validationOptions))) {
			return false;
		}

		// Last component should refer to RTTI3.
		Address rtti3CompAddress = startAddress.add(RTTI_3_OFFSET);
		Address rtti3Address = getReferencedAddress(program, rtti3CompAddress);
		if (rtti3Address == null ||
			(validateReferredToData && !rtti3.isValid(program, rtti3Address, validationOptions))) {
			return false;
		}

		return true;
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "RTTI_4";
	}
}
