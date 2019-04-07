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
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.Msg;

/**
 * The RTTI3 data type represents a ClassHierarchyDescriptor structure.
 * <p>
 * Fields for this RunTimeTypeInformation structure can be found on http://www.openrce.org
 * <p>
 * <pre>
 * struct ClassHierarchyDescriptor {
 *     dword signature;
 *     dword attributes;                  // bit flags
 *     dword numBaseClasses;              // count of RTTI 1 ref entries in RTTI 2 array
 *     4byte_ptr_or_disp pBaseClassArray; // ref to BaseClassArray (RTTI 2)
 * }
 * </pre>
 * <p>
 * RTTI_Class_Hierarchy_Descriptor is the label for the RTTI3 data structure.
 *
 * @deprecated Use of this dynamic data type class is no longer recommended. Instead a 
 * ClassHierarchyDescriptor structure data type can be obtained using the Rtti3Model.
 */
@Deprecated
public class RTTI3DataType extends RTTIDataType {

	private static final int MAX_RTTI_1_COUNT = 1000;
	private final static long serialVersionUID = 1;
	private final static int LENGTH = 16;
	private final static int SIGNATURE_OFFSET = 0;
	private final static int ATTRIBUTES_OFFSET = 4;
	private final static int RTTI_1_COUNT_OFFSET = 8;
	private final static int RTTI_2_POINTER_OFFSET = 12;
	private DataTypeComponent[] fixedComps;

	/**
	 * Creates a dynamic Class Hierarchy Descriptor data type.
	 */
	public RTTI3DataType() {
		this(null);
	}

	/**
	 * Creates a dynamic Class Hierarchy Descriptor data type.
	 * @param dtm the data type manager for this data type.
	 */
	public RTTI3DataType(DataTypeManager dtm) {
		super("RTTI_3", dtm);
		buildFixedComponents();
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new RTTI3DataType(dtm);
	}

	private void buildFixedComponents() {
		fixedComps = new DataTypeComponent[3];
		fixedComps[0] = new ReadOnlyDataTypeComponent(new DWordDataType(), this, 4, 0,
			SIGNATURE_OFFSET, "signature", null);
		fixedComps[1] = new ReadOnlyDataTypeComponent(new DWordDataType(), this, 4, 1,
			ATTRIBUTES_OFFSET, "attributes", "bit flags");
		fixedComps[2] = new ReadOnlyDataTypeComponent(new DWordDataType(), this, 4, 2,
			RTTI_1_COUNT_OFFSET, "numBaseClasses", "number of base classes (i.e. rtti1Count)");
	}

	@Override
	public String getDescription() {
		return "RTTI 3 (RTTI Class Hierarchy Descriptor) Structure";
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "RTTI_3";
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
		long rtti1Count = getRtti1Count(buf.getMemory(), buf.getAddress());
		DataType rtti2Dt = new RTTI2DataType(rtti1Count, dtm);
		DataType rtti2RefDt = getReferenceDataType(program, rtti2Dt);

		DataTypeComponent[] comps = new DataTypeComponent[4];
		System.arraycopy(fixedComps, 0, comps, 0, 3);
		comps[3] = new ReadOnlyDataTypeComponent(rtti2RefDt, this, 4, 3, RTTI_2_POINTER_OFFSET,
			"pBaseClassArray", is64Bit(program) ? "rtti1MapDisplacement" : "rtti1MapPointer");
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
		// RTTI3 should start on a 4 byte boundary.
		if (address.getOffset() % 4 != 0) {
			return 0;
		}
		// RTTI3 is 16 bytes.
		if (bytes.length < LENGTH) {
			return 0;
		}

		// First 8 bytes is 2 dword numeric values.
		// Next four bytes should be number of RTTI1 pointers in RTTI2.
		long rtti1Count = getRtti1Count(memory, address);
		if (rtti1Count < 0 || rtti1Count > 500) { // For now assume we shouldn't be seeing more than 500 pointers in RTTI2.
			return 0;
		}

		// Last component is either a direct reference or an image base offset to RTTI2.
		Address rtti2Address = getRtti2Address(memory, address);
		if (!memory.contains(rtti2Address)) {
			return 0;
		}

		return LENGTH;
	}

	/**
	 * Gets the number of RTTI1 structures that are referred to by an RTTI3 structure being placed
	 * at the rtti3Address of the indicated memory.
	 * @param memory the memory with the data for the RTTI structures.
	 * @param rtti3Address address of an RTTI3 structure
	 * @return the RTTI1 count or 0.
	 */
	public long getRtti1Count(Memory memory, Address rtti3Address) {
		Address rtti1CountAddress = rtti3Address.add(RTTI_1_COUNT_OFFSET);
		try {
			long rtti1Count =
				new Scalar(32, memory.getInt(rtti1CountAddress, memory.isBigEndian())).getValue();
			return rtti1Count;
		}
		catch (MemoryAccessException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			return 0;
		}
	}

	/**
	 * Gets the address of the RTTI2 that is referred to from an RTTI3 structure that is placed at 
	 * the indicated address.
	 * @param memory the memory with the data for the RTTI structures.
	 * @param rtti3Address address of an RTTI3 structure
	 * @return the address of the RTTI2 structure or null.
	 */
	public Address getRtti2Address(Memory memory, Address rtti3Address) {
		Program program = memory.getProgram();
		Address rtti2CompAddress = rtti3Address.add(RTTI_2_POINTER_OFFSET);
		Address pointedToAddress = getReferencedAddress(program, rtti2CompAddress);
		if (pointedToAddress == null || !memory.contains(pointedToAddress)) {
			return null;
		}
		return pointedToAddress;
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
			return false; // Couldn't get enough bytes from memory for an RTTI3.
		}

		if (!validationOptions.shouldIgnoreInstructions() &&
			containsInstruction(listing, startAddress, endAddress)) {
			return false;
		}

		if (!validationOptions.shouldIgnoreDefinedData() &&
			containsDefinedData(listing, startAddress, endAddress)) {
			return false;
		}

		// First 8 bytes is 2 dword numeric values.

		// Next four bytes after 2 dwords should be number of RTTI1 pointers in RTTI2.
		long rtti1Count = getRtti1Count(memory, startAddress);
		if (rtti1Count < 0 || rtti1Count > MAX_RTTI_1_COUNT) { // For now assume we shouldn't be seeing more than 1000 pointers in RTTI2.
			return false;
		}

		boolean validateReferredToData = validationOptions.shouldValidateReferredToData();

		// Last component should refer to RTTI2.
		Address rtti2Address = getRtti2Address(memory, startAddress);
		RTTI2DataType rtti2 = new RTTI2DataType(rtti1Count, program.getDataTypeManager());
		if (rtti2Address == null ||
			(validateReferredToData && !rtti2.isValid(program, rtti2Address, validationOptions))) {
			return false;
		}

		return true;
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "RTTI_3";
	}
}
