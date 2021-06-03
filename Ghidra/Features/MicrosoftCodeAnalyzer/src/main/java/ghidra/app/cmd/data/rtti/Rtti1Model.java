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

import ghidra.app.cmd.data.EHDataTypeUtilities;
import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.util.datatype.microsoft.MSDataTypeUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;

/**
 */
/**
 * Model for run-time type information about the RTTI1 data type, which represents a 
 * BaseClassDescriptor structure.
 * <p>
 * Fields for this RunTimeTypeInformation structure can be found on http://www.openrce.org
 * <p>
 * <pre>
 * struct BaseClassDescriptor {
 *     4byte_ptr_or_disp pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
 *     dword numContainedBases;           // count of extended classes in BaseClassArray (RTTI 2)
 *     struct pmd where;                  // member displacement structure
 *     dword attributes;                  // bit flags
 *     4byte_ptr_or_disp pClassHierarchyDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3) for class
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
 */
public class Rtti1Model extends AbstractCreateRttiDataModel {

	public static final String DATA_TYPE_NAME = "RTTIBaseClassDescriptor";
	private static String STRUCTURE_NAME = "_s__" + DATA_TYPE_NAME;

	private static final int NUM_BASES_ORDINAL = 1;
	private static final int MEMBER_DISP_ORDINAL = 2;
	private static final int ATTRIBUTES_ORDINAL = 3;
	private static final int CLASS_HIERARCHY_POINTER_ORDINAL = 4;

	private static final int TYPE_DESC_POINTER_OFFSET = 0;
	private static final int NUM_BASES_OFFSET = 4;
	private static final int CLASS_HIERARCHY_POINTER_OFFSET = 24;

	private static final int MDISP_ORDINAL = 0;
	private static final int PDISP_ORDINAL = 1;
	private static final int VDISP_ORDINAL = 2;

	private DataType dataType;
	private TypeDescriptorModel rtti0Model;
	private Rtti3Model rtti3Model;

	/**
	 * Creates the model for the BaseClassDescriptor (RTTI 1) data type.
	 * @param program the program
	 * @param rtti1Address the address in the program for the RTTI1 data type.
	 * @param validationOptions options indicating how to validate the data type at the indicated 
	 * address.
	 */
	public Rtti1Model(Program program, Address rtti1Address,
			DataValidationOptions validationOptions) {
		super(program, 1, rtti1Address, validationOptions);
	}

	@Override
	public String getName() {
		return DATA_TYPE_NAME;
	}

	/**
	 * Whether or not the memory at the indicated address appears to be a valid location for the
	 * indicated number of HandlerType data types.
	 * @throws InvalidDataTypeException if this model's location does not appear to be a valid 
	 * group of catch handler entries. The exception has a message indicating
	 * why it does not appear to be a valid location for the data type.
	 */
	@Override
	protected void validateModelSpecificInfo() throws InvalidDataTypeException {

		Program program = getProgram();
		Memory memory = program.getMemory();
		Address startAddress = getAddress();

		DataType rtti1Dt = getDataType();
		DataType baseDt = DataTypeUtils.getBaseDataType(rtti1Dt);
		Structure rtti1Struct = (Structure) baseDt;
		int length = rtti1Dt.getLength();

		// Test that we can get the expected number of bytes.
		MSDataTypeUtils.getBytes(memory, startAddress, length);

		boolean validateReferredToData = validationOptions.shouldValidateReferredToData();

		// First component is either a direct reference or an image base offset.
		Address rtti0Address = getReferencedAddress(program, startAddress);
		if (rtti0Address == null) {
			invalid(); // throws Exception
		}
		rtti0Model = new TypeDescriptorModel(program, rtti0Address, validationOptions);
		if (validateReferredToData) {
			try {
				rtti0Model.validate();
			}
			catch (Exception e) {
				invalid(e); // throws Exception
			}
		}
		else if (!rtti0Model.isLoadedAndInitializedAddress()) {
			invalid("Data referencing " + rtti0Model.getName() +
				" data type isn't a loaded and initialized address " + rtti0Address + ".");
		}

		// Middle bytes are 5 dword numeric values.
		try {
			// numBases should be >= 0
			int numBases = memory.getInt(startAddress.add(NUM_BASES_OFFSET));
			// Check for valid numBases?
			if (numBases < 0) {
				invalid(); // throws Exception
			}

			DataTypeComponent pmdComponent = rtti1Struct.getComponent(MEMBER_DISP_ORDINAL);
			DataType pmdDt = pmdComponent.getDataType();
			DataType baseDataType = DataTypeUtils.getBaseDataType(pmdDt);
			Structure pmdDataType = (Structure) baseDataType;
			int pmdOffset = pmdComponent.getOffset();
			int mdispOffset = pmdDataType.getComponent(MDISP_ORDINAL).getOffset(); // mdisp
			int pdispOffset = pmdDataType.getComponent(PDISP_ORDINAL).getOffset(); // pdisp
			int vdispOffset = pmdDataType.getComponent(VDISP_ORDINAL).getOffset(); // vdisp

			// member displacement should be >= 0
			int mDisp = memory.getInt(startAddress.add(pmdOffset + mdispOffset));
			if (mDisp < 0) {
				invalid(); // throws Exception
			}

			// vbtable displacement should be >= -1
			int pDisp = memory.getInt(startAddress.add(pmdOffset + pdispOffset));
			if (pDisp < -1) {
				invalid(); // throws Exception
			}

			// displacement within vbtable should be >= 0
			int vDisp = memory.getInt(startAddress.add(pmdOffset + vdispOffset));
			if (vDisp < 0) {
				invalid(); // throws Exception
			}

			// attributes can be any bit mask number, so don't check it
//			int attributes = memory.getInt(startAddress.add(ATTRIBUTES_OFFSET));
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			invalid(); // throws Exception
		}

		// Last component is either a direct reference or an image base offset.
		Address rtti3Address =
			getReferencedAddress(program, startAddress.add(CLASS_HIERARCHY_POINTER_OFFSET));
		if (rtti3Address == null) {
			invalid(); // throws Exception
		}
		// Make sure we don't follow flow or will get stuck in infinite loop.
		DataValidationOptions dontFollowOptions = new DataValidationOptions(validationOptions);
		dontFollowOptions.setValidateReferredToData(false);
		rtti3Model = new Rtti3Model(program, rtti3Address, dontFollowOptions);
		if (validateReferredToData) {
			try {
				rtti3Model.validate();
			}
			catch (Exception e) {
				invalid(e); // throws Exception
			}
		}
		else if (!rtti3Model.isLoadedAndInitializedAddress()) {
			invalid("Data referencing " + rtti3Model.getName() +
				" data type isn't a loaded and initialized address " + rtti3Address + ".");
		}
	}

	/**
	 * This gets the BaseClassDescriptor (RTTI 1) structure for the indicated program.
	 * @param program the program which will contain this data type. 
	 * @return the BaseClassDescriptor (RTTI 1) structure.
	 */
	public static DataType getDataType(Program program) {
		// Create simple data types for RTTI 1 &  RTTI 3.
		DataType rtti1Dt = getSimpleDataType(program);
		DataType rtti3Dt = Rtti3Model.getSimpleDataType(program);
		// Now make each refer to the other.
		setRtti3DataType(rtti1Dt, program, rtti3Dt);
		Rtti3Model.setRtti1DataType(rtti3Dt, program, rtti1Dt);
		return MSDataTypeUtils.getMatchingDataType(program, rtti1Dt);
	}

	/**
	 * Make the indicated RTTI 1 refer to the indicated RTTI 3.
	 * @param rtti1Dt the RTTI 1 data type
	 * @param program the program that contains the data types
	 * @param rtti3Dt the RTTI 3 data type
	 */
	static void setRtti3DataType(DataType rtti1Dt, Program program, DataType rtti3Dt) {

		DataTypeManager dataTypeManager = program.getDataTypeManager();
		boolean is64Bit = MSDataTypeUtils.is64Bit(program);
		Structure rtti1Struct = (Structure) DataTypeUtils.getBaseDataType(rtti1Dt);
		DataType rtti3RefDt =
			is64Bit ? new ImageBaseOffset32DataType(dataTypeManager) : new PointerDataType(rtti3Dt);
		rtti1Struct.replace(CLASS_HIERARCHY_POINTER_ORDINAL, rtti3RefDt, rtti3RefDt.getLength(),
			"pClassHierarchyDescriptor", "ref to ClassHierarchyDescriptor (RTTI 3) for class");
	}

	/**
	 * This gets the BaseClassDescriptor (RTTI 1) structure for the indicated program.
	 * @param program the program which will contain this data type. 
	 * @return the BaseClassDescriptor (RTTI 1) structure.
	 */
	static DataType getSimpleDataType(Program program) {

		DataTypeManager dataTypeManager = program.getDataTypeManager();
		boolean is64Bit = MSDataTypeUtils.is64Bit(program);
		DataType rtti0Dt = TypeDescriptorModel.getDataType(program);
		DataType rtti0RefDt =
			is64Bit ? new ImageBaseOffset32DataType(dataTypeManager) : new PointerDataType(rtti0Dt);
		DataType rtti3RefDt =
			is64Bit ? new ImageBaseOffset32DataType(dataTypeManager) : new PointerDataType();

		CategoryPath categoryPath = new CategoryPath(CATEGORY_PATH);
		StructureDataType struct =
			getAlignedPack4Structure(dataTypeManager, categoryPath, STRUCTURE_NAME);

		// Add the components.
		struct.add(rtti0RefDt, "pTypeDescriptor", "ref to TypeDescriptor (RTTI 0) for class");
		DWordDataType dWordDataType = new DWordDataType(dataTypeManager);
		struct.add(dWordDataType, "numContainedBases",
			"count of extended classes in BaseClassArray (RTTI 2)");
		Structure pmdDataType = MSDataTypeUtils.getPMDDataType(program);
		struct.add(pmdDataType, "where", "member displacement structure");
		struct.add(dWordDataType, "attributes", "bit flags");
		struct.add(rtti3RefDt, "pClassHierarchyDescriptor",
			"ref to ClassHierarchyDescriptor (RTTI 3) for class");

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
	 * Gets the address of the RTTI 0 structure that is referred to by a component of this RTTI 1.
	 * @return the address of the RTTI 0
	 * @throws InvalidDataTypeException if this isn't a valid model at the specified address.
	 */
	public Address getRtti0Address() throws InvalidDataTypeException {

		checkValidity();
		Program program = getProgram();
		Address rtti1Address = getAddress();
		Address rtti0ComponentAddress = rtti1Address.add(TYPE_DESC_POINTER_OFFSET);
		return getReferencedAddress(program, rtti0ComponentAddress);
	}

	/**
	 * Gets the number of extended base classes in the base class array.
	 * @return the number of base classes
	 * @throws InvalidDataTypeException if this isn't a valid model at the specified address.
	 */
	public int getNumBases() throws InvalidDataTypeException {
		checkValidity();
		return EHDataTypeUtilities.getIntegerValue(getDataType(), NUM_BASES_ORDINAL,
			getMemBuffer());
	}

	private int getPmdValue(int pmdOrdinal) throws InvalidDataTypeException {
		checkValidity();
		DataType rtti1Dt = getDataType();
		DataType baseDt = DataTypeUtils.getBaseDataType(rtti1Dt);
		Structure rtti1Struct = (Structure) baseDt;
		DataTypeComponent component = rtti1Struct.getComponent(MEMBER_DISP_ORDINAL);
		int pmdOffset = component.getOffset();
		Address rtti1Address = getAddress();
		Address pmdAddress = rtti1Address.add(pmdOffset);
		DataType pmdDataType = component.getDataType();
		MemBuffer pmdMemBuffer = new DumbMemBufferImpl(getProgram().getMemory(), pmdAddress);
		return EHDataTypeUtilities.getIntegerValue(pmdDataType, pmdOrdinal, pmdMemBuffer);
	}

	/**
	 * Gets the member displacement for this RTTI 1.
	 * @return the member displacement
	 * @throws InvalidDataTypeException if this isn't a valid model at the specified address.
	 */
	public int getMDisp() throws InvalidDataTypeException {
		return getPmdValue(MDISP_ORDINAL);
	}

	/**
	 * Gets the vbtable displacement for this RTTI 1.
	 * @return the vbtable displacement
	 * @throws InvalidDataTypeException if this isn't a valid model at the specified address.
	 */
	public int getPDisp() throws InvalidDataTypeException {
		return getPmdValue(PDISP_ORDINAL);
	}

	/**
	 * Gets the displacement within the vbtable for this RTTI 1.
	 * @return the displacement in the vbtable
	 * @throws InvalidDataTypeException if this isn't a valid model at the specified address.
	 */
	public int getVDisp() throws InvalidDataTypeException {
		return getPmdValue(VDISP_ORDINAL);
	}

	/**
	 * Gets the value of the attributes field for this RTTI 1.
	 * @return the attributes.
	 * @throws InvalidDataTypeException if this isn't a valid model at the specified address.
	 */
	public int getAttributes() throws InvalidDataTypeException {
		checkValidity();
		return EHDataTypeUtilities.getIntegerValue(getDataType(), ATTRIBUTES_ORDINAL,
			getMemBuffer());
	}

	/**
	 * Gets the address of the RTTI 3 structure that is referred to by a component of this RTTI 1.
	 * @return the address of the RTTI 3
	 * @throws InvalidDataTypeException if this isn't a valid model at the specified address.
	 */
	public Address getRtti3Address() throws InvalidDataTypeException {

		checkValidity();
		Program program = getProgram();
		Address rtti1Address = getAddress();
		Address rtti3ComponentAddress = rtti1Address.add(CLASS_HIERARCHY_POINTER_OFFSET);
		return getReferencedAddress(program, rtti3ComponentAddress);
	}

	@Override
	public boolean refersToRtti0(Address rtti0Address) {

		Address referredToAddress;
		try {
			referredToAddress = getRtti0Address();
		}
		catch (InvalidDataTypeException e) {
			return false;
		}
		return rtti0Address.equals(referredToAddress);
	}

	/**
	 * Gets the type descriptor (RTTI 0) model associated with this RTTI 1.
	 * @return the type descriptor (RTTI 0) model or null.
	 */
	public TypeDescriptorModel getRtti0Model() {
		try {
			checkValidity();
		}
		catch (InvalidDataTypeException e) {
			return null;
		}
		return rtti0Model;
	}

	/**
	 * Gets the BaseClassDescriptor (RTTI 3) model associated with this RTTI 1.
	 * @return the BaseClassDescriptor (RTTI 3) model or null.
	 */
	public Rtti3Model getRtti3Model() {
		try {
			checkValidity();
		}
		catch (InvalidDataTypeException e) {
			return null;
		}
		return rtti3Model;
	}
}
