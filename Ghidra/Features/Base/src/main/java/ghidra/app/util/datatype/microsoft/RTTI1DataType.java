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
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;

/**
 * The RTTI1 data type represents a BaseClassDescriptor structure.
 * <p>
 * Fields for this RunTimeTypeInformation structure can be found on http://www.openrce.org
 * <p>
 * <pre>
 * struct BaseClassDescriptor {
 *     4byte_ptr_or_disp pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
 *     dword numContainedBases;           // count of extended classes in BaseClassArray (RTTI 2)
 *     struct pmd where;                  // member displacement structure
 *     dword attributes;                  // bit flags
 * }
 * </pre>
 * <p>
 * <pre>
 * struct pmd {
 *     int mdisp; // member displacement
 *     int pdisp; // vbtable displacement
 *     int vdisp; // displacement within vbtable
 * }
 * </pre>
 * <p>
 * RTTI_Base_Class_Descriptor is the label for the RTTI1 data structure.
 *
 * @deprecated Use of this dynamic data type class is no longer recommended. Instead a
 * BaseClassDescriptor structure data type can be obtained using the Rtti1Model.
 */
@Deprecated
public class RTTI1DataType extends RTTIDataType {

	private final static long serialVersionUID = 1;

	// PMD fields
	private final static int PMD_LENGTH = 12;
	private final static int M_DISP_OFFSET = 0;
	private final static int P_DISP_OFFSET = 4;
	private final static int V_DISP_OFFSET = 8;

	// RTTI 1 fields
	private final static int LENGTH = 28;
	private final static int RTTI_0_OFFSET = 0;
	private final static int NUM_CONTAINED_BASES_OFFSET = 4;
	// Commented the following out and replaced it with offset of PMD structure.
	// Leaving it in until we are certain we want the actual PMD structure in this dynamic data type.
//	private final static int PMD_MDISP_OFFSET = 8;
//	private final static int PMD_PDISP_OFFSET = 12;
//	private final static int PMD_VDISP_OFFSET = 16;
	private final static int PMD_OFFSET = 8;
	private final static int ATTRIBUTES_OFFSET = 20;
	private final static int RTTI_3_OFFSET = 24;

	private RTTI0DataType rtti0;
	private RTTI3DataType rtti3;

	/**
	 * Creates a dynamic Base Class Descriptor data type.
	 */
	public RTTI1DataType() {
		this(null);
	}

	/**
	 * Creates a dynamic Base Class Descriptor data type.
	 * @param dtm the data type manager for this data type.
	 */
	public RTTI1DataType(DataTypeManager dtm) {
		super("RTTI_1", dtm);
		rtti0 = new RTTI0DataType(dtm);
		rtti3 = new RTTI3DataType(dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new RTTI1DataType(dtm);
	}

	@Override
	public String getDescription() {
		return "RTTI 1 (RTTI Base Class Descriptor) Structure";
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "RTTI_1";
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
		DataType rtti0RefDt = getReferenceDataType(program, rtti0Dt);
		DataType rtti3Dt = new RTTI3DataType(dtm);
		DataType rtti3RefDt = getReferenceDataType(program, rtti3Dt);

		DataTypeComponent[] comps = new DataTypeComponent[5];
		comps[0] = new ReadOnlyDataTypeComponent(rtti0RefDt, this, 4, 0, RTTI_0_OFFSET,
			"pTypeDescriptor", is64Bit(program) ? "rtti0Displacement" : "rtti0Pointer");
		comps[1] = new ReadOnlyDataTypeComponent(new DWordDataType(), this, 4, 1,
			NUM_CONTAINED_BASES_OFFSET, "numContainedBases",
			"number of direct bases of this base class");

		// Commented the following out and replaced it with a PMD structure data type.
		// Leaving it in until we are certain we want the actual PMD structure in this dynamic data type.
//		comps[2] = new ReadOnlyDataTypeComponent(new DWordDataType(), this, 4, 2, PMD_MDISP_OFFSET,
//			"PMD.mdisp", "vftable offset");
//		comps[3] = new ReadOnlyDataTypeComponent(new DWordDataType(), this, 4, 3, PMD_PDISP_OFFSET,
//			"PMD.pdisp",
//			"vbtable offset (-1: vftable is at displacement PMD.mdisp inside the class)");
//		comps[4] = new ReadOnlyDataTypeComponent(new DWordDataType(), this, 4, 4, PMD_VDISP_OFFSET,
//			"PMD.vdisp", "Displacement of the base class vftable pointer inside the vbtable");
		Structure pmdDataType = MSDataTypeUtils.getPMDDataType(program);
		comps[2] = new ReadOnlyDataTypeComponent(pmdDataType, this, PMD_LENGTH, 2, PMD_OFFSET,
			"where", "");

		comps[3] = new ReadOnlyDataTypeComponent(new DWordDataType(), this, 4, 3, ATTRIBUTES_OFFSET,
			"attributes", null);
		comps[4] = new ReadOnlyDataTypeComponent(rtti3RefDt, this, 4, 4, RTTI_3_OFFSET,
			"pClassHierarchyDescriptor", is64Bit(program) ? "rtti3Displacement" : "rtti3Pointer");

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
		// RTTI1 should start on a 4 byte boundary.
		if (address.getOffset() % 4 != 0) {
			return 0;
		}
		// RTTI1 is 28 bytes.
		if (bytes.length < LENGTH) {
			return 0;
		}

		// First component is either a direct reference or an image base offset.
		Address pointedToAddress = getReferencedAddress(program, address);
		if (pointedToAddress == null || !memory.contains(pointedToAddress)) {
			return 0;
		}

		return LENGTH;
	}

	/**
	 * Gets the address of the RTTI 0 or null if one isn't indicated.
	 * @param memory the program memory containing the address
	 * @param rtti1Address the address for the RTTI 1 that refers to the RTTI 0
	 * @return the address of the RTTI 0 or null.
	 */
	public Address getRtti0Address(Memory memory, Address rtti1Address) {
		return getRtti0Address(memory.getProgram(), rtti1Address);
	}

	/**
	 * Gets the address of the RTTI 0 or null if one isn't indicated.
	 * @param program the program  containing the address
	 * @param rtti1Address the address for the RTTI 1 that refers to the RTTI 0
	 * @return the address of the RTTI 0 or null.
	 */
	public Address getRtti0Address(Program program, Address rtti1Address) {
		Address rtti0ComponentAddress = rtti1Address.add(RTTI_0_OFFSET);
		return getReferencedAddress(program, rtti0ComponentAddress);
	}

	@Override
	public boolean isValid(Program program, Address startAddress,
			DataValidationOptions validationOptions) {

		Memory memory = program.getMemory();
		Listing listing = program.getListing();

		if (!memory.contains(startAddress)) {
			return false;
		}

		Address endAddress = startAddress.add(LENGTH - 1);
		try {
			MSDataTypeUtils.getBytes(memory, startAddress, LENGTH);
		}
		catch (InvalidDataTypeException e) {
			return false; // Couldn't get enough bytes from memory for an RTTI1.
		}

		if (!validationOptions.shouldIgnoreInstructions() &&
			containsInstruction(listing, startAddress, endAddress)) {
			return false;
		}

		if (!validationOptions.shouldIgnoreDefinedData() &&
			containsDefinedData(listing, startAddress, endAddress)) {
			return false;
		}

		// RTTI1 should start on 4 byte boundary.
		if (startAddress.getOffset() % 4 != 0) {
			return false;
		}

		return validateComponents(program, startAddress, validationOptions);
	}

	private boolean validateComponents(Program program, Address startAddress,
			DataValidationOptions validationOptions) {

		boolean validateReferredToData = validationOptions.shouldValidateReferredToData();
		Memory memory = program.getMemory();

		// First component is either a direct reference or an image base offset.
		Address rtti0Address = getReferencedAddress(program, startAddress);
		if (rtti0Address == null ||
			(validateReferredToData && !rtti0.isValid(program, rtti0Address, validationOptions))) {
			return false;
		}
		// Middle bytes are 5 dword numeric values.
		try {
			// numBases should be >= 0 
			int numBases = memory.getInt(startAddress.add(NUM_CONTAINED_BASES_OFFSET));
			if (numBases < 0) {
				return false;
			}
			// member displacement should be >= 0 
			int mDisp = memory.getInt(startAddress.add(PMD_OFFSET + M_DISP_OFFSET));
			if (mDisp < 0) {
				return false;
			}
			// vbtable displacement should be >= -1
			int pDisp = memory.getInt(startAddress.add(PMD_OFFSET + P_DISP_OFFSET));
			if (pDisp < -1) {
				return false;
			}
			// displacement within vbtable should be >= 0 
			int vDisp = memory.getInt(startAddress.add(PMD_OFFSET + V_DISP_OFFSET));
			if (vDisp < 0) {
				return false;
			}
			// attributes can be any bitmask number so don't check it
//			int attributes = memory.getInt(startAddress.add(ATTRIBUTES_OFFSET));
		}
		catch (MemoryAccessException e) {
			return false;
		}
		catch (AddressOutOfBoundsException e) {
			return false;
		}
		// Last component is either a direct reference or an image base offset.
		Address rtti3Address = getReferencedAddress(program, startAddress.add(RTTI_3_OFFSET));
		// Make sure we don't follow flow or validation will get stuck in infinite loop.
		DataValidationOptions dontFollowOptions = new DataValidationOptions(validationOptions);
		dontFollowOptions.setValidateReferredToData(false);
		if (rtti3Address == null ||
			(validateReferredToData && !rtti3.isValid(program, rtti3Address, dontFollowOptions))) {
			return false;
		}
		return true;
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "RTTI_1";
	}
}
