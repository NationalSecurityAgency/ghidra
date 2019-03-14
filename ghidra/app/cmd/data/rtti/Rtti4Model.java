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

import java.util.List;

import ghidra.app.cmd.data.EHDataTypeUtilities;
import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.util.datatype.microsoft.MSDataTypeUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

/**
 * Model for run-time type information about the RTTI4 data type, which represents a 
 * CompleteObjectLocator structure.
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
 */
public class Rtti4Model extends AbstractCreateRttiDataModel {

	public static final String DATA_TYPE_NAME = "RTTICompleteObjectLocator";
	private static String STRUCTURE_NAME = "_s__" + DATA_TYPE_NAME;

	private final static int SIGNATURE_ORDINAL = 0;
	private final static int VB_TABLE_OFFSET_ORDINAL = 1;
	private final static int CONSTRUCTOR_DISP_OFFSET_ORDINAL = 2;

	private final static int SIGNATURE_OFFSET = 0;
	private final static int VB_TABLE_OFFSET_OFFSET = 4;
	private final static int CONSTRUCTOR_DISP_OFFSET_OFFSET = 8;
	private final static int RTTI_0_PTR_OFFSET = 12;
	private final static int RTTI_3_PTR_OFFSET = 16;

	private DataType dataType;
	private TypeDescriptorModel rtti0Model;
	private Rtti3Model rtti3Model;

	/**
	 * Creates the model for the RTTI4 data type.
	 * @param program the program
	 * @param rtti4Address the address in the program for the RTTI4 data
	 * types.
	 * @param validationOptions options indicating how to validate the data type at the indicated 
	 * address.
	 */
	public Rtti4Model(Program program, Address rtti4Address,
			DataValidationOptions validationOptions) {
		super(program, 1, rtti4Address, validationOptions);
	}

	@Override
	public String getName() {
		return DATA_TYPE_NAME;
	}

	@Override
	public void validateModelSpecificInfo() throws InvalidDataTypeException {

		Program program = getProgram();
		Address startAddress = getAddress();
		boolean validateReferredToData = validationOptions.shouldValidateReferredToData();

		// Num1 is dword at SIGNATURE_OFFSET.
		// No additional validation for this yet.

		// Num2 is dword at VB_TABLE_OFFSET_OFFSET.
		// No additional validation for this yet.

		// Num3 is dword at CONSTRUCTOR_DISP_OFFSET_OFFSET.
		// No additional validation for this yet.

		// Next component should refer to RTTI0.
		Address rtti0CompAddress = startAddress.add(RTTI_0_PTR_OFFSET);
		Address rtti0Address = getReferencedAddress(program, rtti0CompAddress);
		if (rtti0Address == null) {
			throw new InvalidDataTypeException(getName() + " data type at " + getAddress() +
				" doesn't refer to a valid location " + rtti0Address + " for the Type Descriptor.");
		}
		rtti0Model = new TypeDescriptorModel(program, rtti0Address, validationOptions);
		if (validateReferredToData) {
			rtti0Model.validate();
		}
		else if (!rtti0Model.isLoadedAndInitializedAddress()) {
			throw new InvalidDataTypeException("Data referencing " + rtti0Model.getName() +
				" data type isn't a loaded and initialized address " + rtti0Address + ".");
		}

		// Last 4 bytes should refer to RTTI3.
		Address rtti3CompAddress = startAddress.add(RTTI_3_PTR_OFFSET);
		Address rtti3Address = getReferencedAddress(program, rtti3CompAddress);
		if (rtti3Address == null) {
			throw new InvalidDataTypeException(getName() + " data type at " + getAddress() +
				" doesn't refer to a valid location for the Class Hierarchy Descriptor.");
		}
		rtti3Model = new Rtti3Model(program, rtti3Address, validationOptions);
		if (validateReferredToData) {
			rtti3Model.validate();
		}
		else if (!rtti3Model.isLoadedAndInitializedAddress()) {
			throw new InvalidDataTypeException("Data referencing " + rtti3Model.getName() +
				" data type isn't a loaded and initialized address " + rtti3Address + ".");
		}
	}

	/**
	 * This gets the CompleteObjectLocator (RTTI 4) structure for the indicated program.
	 * @param program the program which will contain this data type. 
	 * @return the CompleteObjectLocator (RTTI 4) structure.
	 */
	public static DataType getDataType(Program program) {

		DataTypeManager dataTypeManager = program.getDataTypeManager();

		CategoryPath categoryPath = new CategoryPath(CATEGORY_PATH);
		StructureDataType struct =
			getAlignedPack4Structure(dataTypeManager, categoryPath, STRUCTURE_NAME);

		// Add the components.
		DWordDataType dWordDataType = new DWordDataType(dataTypeManager);
		struct.add(dWordDataType, "signature", null);
		struct.add(dWordDataType, "offset", "offset of vbtable within class");
		struct.add(dWordDataType, "cdOffset", "constructor displacement offset");

		DataType rtti0RefDt =
			getReferenceDataType(program, TypeDescriptorModel.getDataType(program));
		struct.add(rtti0RefDt, "pTypeDescriptor", "ref to TypeDescriptor (RTTI 0) for class");

		DataType rtti3Dt = Rtti3Model.getDataType(program);
		DataType rtti3RefDt = getReferenceDataType(program, rtti3Dt);
		struct.add(rtti3RefDt, "pClassDescriptor", "ref to ClassHierarchyDescriptor (RTTI 3)");

		TypedefDataType typedefDt =
			new TypedefDataType(categoryPath, DATA_TYPE_NAME, struct, dataTypeManager);

		return MSDataTypeUtils.getMatchingDataType(program, typedefDt);
	}

	/**
	 * Gets the offset of the field in this RTTI 4 that has the signature.
	 * @return the offset of the signature
	 */
	public static int getSignatureComponentOffset() {
		return SIGNATURE_OFFSET;
	}

	/**
	 * Gets the offset of the field in this RTTI 4 that has the offset of the vb table in the class.
	 * @return the offset of the vb table offset
	 */
	public static int getVBTableComponentOffset() {
		return VB_TABLE_OFFSET_OFFSET;
	}

	/**
	 * Gets the offset of the field in this RTTI 4 that has the constructor displacement offset.
	 * @return the offset of the constructor displacement offset
	 */
	public static int getConstructorDisplacementComponentOffset() {
		return CONSTRUCTOR_DISP_OFFSET_OFFSET;
	}

	/**
	 * Gets the offset of the field in this RTTI 4 that has the RTTI 0 pointer.
	 * @return the offset of the RTTI 0 pointer
	 */
	public static int getRtti0PointerComponentOffset() {
		return RTTI_0_PTR_OFFSET;
	}

	/**
	 * Gets the offset of the field in this RTTI 4 that has the RTTI 3 pointer.
	 * @return the offset of the RTTI 3 pointer
	 */
	public static int getRtti3PointerComponentOffset() {
		return RTTI_3_PTR_OFFSET;
	}

	/**
	 * Gets the address of the component for the RTTI 0 pointer.
	 * @return the component address of the RTTI 0 pointer
	 * @throws InvalidDataTypeException if this isn't a valid model at the specified address.
	 */
	public Address getRtti0FieldAddress() throws InvalidDataTypeException {
		checkValidity();
		return getAddress().add(RTTI_0_PTR_OFFSET);
	}

	/**
	 * Gets the address of the component for the RTTI 3 pointer.
	 * @return the component address of the RTTI 3 pointer
	 * @throws InvalidDataTypeException if this isn't a valid model at the specified address.
	 */
	public Address getRtti3FieldAddress() throws InvalidDataTypeException {
		checkValidity();
		return getAddress().add(RTTI_3_PTR_OFFSET);
	}

	/**
	 * Gets the signature value in this RTTI 4.
	 * @return the signature value
	 * @throws InvalidDataTypeException if this isn't a valid model at the specified address.
	 */
	public int getSignature() throws InvalidDataTypeException {
		checkValidity();
		return EHDataTypeUtilities.getIntegerValue(getDataType(), SIGNATURE_ORDINAL,
			getMemBuffer());
	}

	/**
	 * Gets the virtual base table offset in this RTTI 4.
	 * @return the vb table offset
	 * @throws InvalidDataTypeException if this isn't a valid model at the specified address.
	 */
	public int getVbTableOffset() throws InvalidDataTypeException {
		checkValidity();
		return EHDataTypeUtilities.getIntegerValue(getDataType(), VB_TABLE_OFFSET_ORDINAL,
			getMemBuffer());
	}

	/**
	 * Gets the constructor displacement offset in this RTTI 4.
	 * @return the constructor displacement offset
	 * @throws InvalidDataTypeException if this isn't a valid model at the specified address.
	 */
	public int getConstructorOffset() throws InvalidDataTypeException {
		checkValidity();
		return EHDataTypeUtilities.getIntegerValue(getDataType(), CONSTRUCTOR_DISP_OFFSET_ORDINAL,
			getMemBuffer());
	}

	/**
	 * Gets the address of the RTTI 0 structure that is pointed to by this RTTI 4.
	 * @return the address of the RTTI 0
	 * @throws InvalidDataTypeException if this isn't a valid model at the specified address.
	 */
	public Address getRtti0Address() throws InvalidDataTypeException {
		checkValidity();
		Address rtti0CompAddress = getAddress().add(RTTI_0_PTR_OFFSET);
		return getReferencedAddress(getProgram(), rtti0CompAddress);
	}

	/**
	 * Gets the address of the RTTI 3 structure that is pointed to by this RTTI 4.
	 * @return the address of the RTTI 3
	 * @throws InvalidDataTypeException if this isn't a valid model at the specified address.
	 */
	public Address getRtti3Address() throws InvalidDataTypeException {
		checkValidity();
		Address rtti3CompAddress = getAddress().add(RTTI_3_PTR_OFFSET);
		return getReferencedAddress(getProgram(), rtti3CompAddress);
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

	@Override
	public boolean refersToRtti0(Address rtti0Address) {

		// Check the RTTI 0 reference in this RTTI 4.
		Address rtti0AddressInRtti4;
		try {
			checkValidity();
			rtti0AddressInRtti4 = getRtti0Address();

			if (rtti0AddressInRtti4 == null || !rtti0AddressInRtti4.equals(rtti0Address)) {
				return false;
			}

			// Check the RTTI 0 reference that should be reached via the RTTI 3 reference.
			return rtti3Model.refersToRtti0(rtti0Address);
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
		return rtti3Model.getBaseClassTypes();
	}

	/**
	 * Gets the type descriptor (RTTI 0) model associated with this RTTI 4.
	 * @return the type descriptor (RTTI 0) model or null.
	 * @throws InvalidDataTypeException if this model's validation fails.
	 */
	public TypeDescriptorModel getRtti0Model() throws InvalidDataTypeException {
		checkValidity();
		return rtti0Model;
	}

	/**
	 * Gets the ClassHierarchyDescriptor (RTTI 3) model associated with this RTTI 4.
	 * @return the ClassHierarchyDescriptor (RTTI 3) model or null.
	 * @throws InvalidDataTypeException if this model's validation fails.
	 */
	public Rtti3Model getRtti3Model() throws InvalidDataTypeException {
		checkValidity();
		return rtti3Model;
	}

}
