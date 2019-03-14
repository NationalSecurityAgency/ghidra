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

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAlignedPack4Structure;
import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getReferencedAddress;

import java.util.List;

import ghidra.app.cmd.data.EHDataTypeUtilities;
import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.util.datatype.microsoft.MSDataTypeUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.Msg;

/**
 * Model for run-time type information about the RTTI3 data type, which represents a
 * ClassHierarchyDescriptor structure.
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
 */
public class Rtti3Model extends AbstractCreateRttiDataModel {

	public static final String DATA_TYPE_NAME = "RTTIClassHierarchyDescriptor";
	private static String STRUCTURE_NAME = "_s__" + DATA_TYPE_NAME;

	private static final int SIGNATURE_ORDINAL = 0;
	private static final int ATTRIBUTES_ORDINAL = 1;
	private static final int BASE_ARRAY_PTR_ORDINAL = 3;

	private static final int NUM_BASES_OFFSET = 8;
	private static final int BASE_ARRAY_PTR_OFFSET = 12;
	private static final long MAX_RTTI_1_COUNT = 1000;

	private DataType dataType;
	private Rtti2Model rtti2Model;

	/**
	 * Creates the model for the RTTI3 data type.
	 * @param program the program
	 * @param rtti3Address the address in the program for the RTTI3 data
	 * types.
	 * @param validationOptions options indicating how to validate the data type at the indicated 
	 * address.
	 */
	public Rtti3Model(Program program, Address rtti3Address,
			DataValidationOptions validationOptions) {
		super(program, rtti3Address, validationOptions);
	}

	@Override
	public String getName() {
		return DATA_TYPE_NAME;
	}

	@Override
	protected void validateModelSpecificInfo() throws InvalidDataTypeException {

		Program program = getProgram();

		// Num1 is dword at SIGNATURE_OFFSET.
		// No additional validation for this yet.

		// Num2 is dword at ATTRIBUTES_OFFSET.
		// No additional validation for this yet.

		// Next four bytes after 2 dwords should be number of RTTI1 pointers in RTTI2.
		int rtti1Count = getRtti1Count();
		if (rtti1Count < 1 || rtti1Count > MAX_RTTI_1_COUNT) { // For now assume we shouldn't be seeing more than 1000 pointers in RTTI2.
			throw new InvalidDataTypeException(getName() + " data type at " + getAddress() +
				" doesn't have a valid " + Rtti1Model.DATA_TYPE_NAME + " count.");
		}

		boolean validateReferredToData = validationOptions.shouldValidateReferredToData();

		// Last component should refer to RTTI2.
		Address rtti2Address = getRtti2Address();
		if (rtti2Address == null) {
			throw new InvalidDataTypeException(getName() + " data type at " + getAddress() +
				" doesn't refer to a valid location for the " + Rtti2Model.DATA_TYPE_NAME + ".");
		}
		rtti2Model = new Rtti2Model(program, rtti1Count, rtti2Address, validationOptions);
		if (validateReferredToData) {
			rtti2Model.validate();
		}
		else if (!rtti2Model.isLoadedAndInitializedAddress()) {
			throw new InvalidDataTypeException("Data referencing " + rtti2Model.getName() +
				" data type isn't a loaded and initialized address " + rtti2Address + ".");
		}
	}

	/**
	 * This gets the ClassHierarchyDescriptor (RTTI 3) structure for the indicated program.
	 * @param program the program which will contain this data type. 
	 * @return the ClassHierarchyDescriptor (RTTI 3) structure.
	 */
	public static DataType getDataType(Program program) {
		// Create simple data types for RTTI 1 &  RTTI 3.
		DataType rtti3Dt = getSimpleDataType(program);
		DataType rtti1Dt = Rtti1Model.getSimpleDataType(program);
		// Now make each refer to the other.
		setRtti1DataType(rtti3Dt, program, rtti1Dt);
		Rtti1Model.setRtti3DataType(rtti1Dt, program, rtti3Dt);
		return MSDataTypeUtils.getMatchingDataType(program, rtti3Dt);
	}

	/**
	 * Make the indicated RTTI 3 refer to the indicated RTTI 1 through the RTTI 2 reference.
	 * @param rtti3Dt the RTTI 3 data type
	 * @param program the program that contains the data types
	 * @param rtti1Dt the RTTI 1 data type
	 */
	static void setRtti1DataType(DataType rtti3Dt, Program program, DataType rtti1Dt) {

		DataTypeManager dataTypeManager = program.getDataTypeManager();
		boolean is64Bit = MSDataTypeUtils.is64Bit(program);
		Structure rtti3Struct = (Structure) DataTypeUtils.getBaseDataType(rtti3Dt);
		DataType individualRtti2EntryDt = Rtti2Model.getIndividualEntryDataType(program, rtti1Dt);
		DataType rtti2RefDt = is64Bit ? new ImageBaseOffset32DataType(dataTypeManager)
				: new PointerDataType(individualRtti2EntryDt);
		rtti3Struct.replace(BASE_ARRAY_PTR_ORDINAL, rtti2RefDt, rtti2RefDt.getLength(),
			"pBaseClassArray", "ref to BaseClassArray (RTTI 2)");
	}

	/**
	 * This gets the ClassHierarchyDescriptor (RTTI 3) structure for the indicated program.
	 * @param program the program which will contain this data type. 
	 * @return the ClassHierarchyDescriptor (RTTI 3) structure.
	 */
	static DataType getSimpleDataType(Program program) {

		DataTypeManager dataTypeManager = program.getDataTypeManager();
		boolean is64Bit = MSDataTypeUtils.is64Bit(program);

		CategoryPath categoryPath = new CategoryPath(CATEGORY_PATH);
		StructureDataType struct =
			getAlignedPack4Structure(dataTypeManager, categoryPath, STRUCTURE_NAME);

		// Add the components.
		DWordDataType dWordDataType = new DWordDataType(dataTypeManager);
		struct.add(dWordDataType, "signature", null);
		struct.add(dWordDataType, "attributes", "bit flags");
		struct.add(dWordDataType, "numBaseClasses", "number of base classes (i.e. rtti1Count)");

		DataType rtti2Dt = Rtti2Model.getSimpleIndividualEntryDataType(program);
		DataType rtti2RefDt =
			is64Bit ? new ImageBaseOffset32DataType(dataTypeManager) : new PointerDataType(rtti2Dt);
		struct.add(rtti2RefDt, "pBaseClassArray", "ref to BaseClassArray (RTTI 2)");

		return new TypedefDataType(categoryPath, DATA_TYPE_NAME, struct, dataTypeManager);
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
		return getDataType().getLength();
	}

	/**
	 * Gets the signature value from this RTTI 3.
	 * @return the signature value
	 * @throws InvalidDataTypeException if this isn't a valid model at the specified address.
	 */
	public int getSignature() throws InvalidDataTypeException {
		checkValidity();
		return EHDataTypeUtilities.getIntegerValue(getDataType(), SIGNATURE_ORDINAL,
			getMemBuffer());
	}

	/**
	 * Gets the attributes value from this RTTI3.
	 * @return the attributes
	 * @throws InvalidDataTypeException if this isn't a valid model at the specified address.
	 */
	public int getAttributes() throws InvalidDataTypeException {
		checkValidity();
		return EHDataTypeUtilities.getIntegerValue(getDataType(), ATTRIBUTES_ORDINAL,
			getMemBuffer());
	}

	/**
	 * Gets the number of RTTI1 structures that are referred to by an RTTI3 structure being placed
	 * at the rtti3Address of the indicated memory.
	 * @return the RTTI1 count or 0.
	 * @throws InvalidDataTypeException if this isn't a valid model at the specified address.
	 */
	public int getRtti1Count() throws InvalidDataTypeException {

		checkValidity();
		Address rtti3Address = getAddress();
		return getRtti1Count(getProgram(), rtti3Address);
	}

	public static int getRtti1Count(Program program, Address rtti3Address) {

		Memory memory = program.getMemory();

		Address rtti1CountAddress = rtti3Address.add(NUM_BASES_OFFSET);
		int rtti1Count = 0;
		try {
			rtti1Count =
				(int) new Scalar(32, memory.getInt(rtti1CountAddress, memory.isBigEndian()))
					.getValue();
			return rtti1Count;
		}
		catch (MemoryAccessException e) {
			Msg.error(Rtti3Model.class, "Unexpected Exception: " + e.getMessage(), e);
			return 0;
		}
	}

	/**
	 * Gets the address of the RTTI2 that is referred to from an RTTI3 structure that is placed at 
	 * the indicated address.
	 * @return the address of the RTTI2 structure or null.
	 * @throws InvalidDataTypeException if this isn't a valid model at the specified address.
	 */
	public Address getRtti2Address() throws InvalidDataTypeException {

		checkValidity();
		return getRtti2Address(getProgram(), getAddress());
	}

	private static Address getRtti2Address(Program program, Address rtti3Address) {

		Memory memory = program.getMemory();

		Address rtti2CompAddress = rtti3Address.add(BASE_ARRAY_PTR_OFFSET);
		Address pointedToAddress = getReferencedAddress(program, rtti2CompAddress);
		if (pointedToAddress == null || !memory.contains(pointedToAddress)) {
			return null;
		}
		return pointedToAddress;
	}

	@Override
	public boolean refersToRtti0(Address rtti0Address) {

		try {
			checkValidity();
			return rtti2Model.refersToRtti0(rtti0Address);
		}
		catch (InvalidDataTypeException e) {
			return false;
		}
	}

	/**
	 * Get the Base Class Types (type descriptor names) for the RTTI for this model.
	 * @return the class names or an empty list if the name(s) can't be determined.
	 * @throws InvalidDataTypeException if an invalid model is encountered when trying to get
	 * the base class types. The exception has a message indicating
	 * why it does not appear to be a valid location for the data type.
	 */
	public List<String> getBaseClassTypes() throws InvalidDataTypeException {

		checkValidity();
		return rtti2Model.getBaseClassTypes();
	}

	/**
	 * Gets the type descriptor (RTTI 0) model associated with this RTTI 3.
	 * @return the type descriptor (RTTI 0) model or null.
	 * @throws InvalidDataTypeException if this model's validation fails.
	 */
	public TypeDescriptorModel getRtti0Model() throws InvalidDataTypeException {
		checkValidity();
		return rtti2Model.getRtti0Model();
	}

	/**
	 * Gets the BaseClassArray (RTTI 2) model associated with this RTTI 3.
	 * @return the BaseClassArray (RTTI 2) model or null.
	 * @throws InvalidDataTypeException if this model's validation fails.
	 */
	public Rtti2Model getRtti2Model() throws InvalidDataTypeException {
		checkValidity();
		return rtti2Model;
	}

}
