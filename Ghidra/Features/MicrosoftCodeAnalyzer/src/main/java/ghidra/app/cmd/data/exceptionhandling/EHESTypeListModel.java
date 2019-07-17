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
package ghidra.app.cmd.data.exceptionhandling;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAlignedPack4Structure;

import ghidra.app.cmd.data.AbstractCreateDataTypeModel;
import ghidra.app.cmd.data.EHDataTypeUtilities;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.util.datatype.microsoft.MSDataTypeUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

/**
 * Model for exception handling information about the ESTypeList data type and its 
 * associated exception handling data types.
 * <br>
 * This is based on data type information from ehdata.h
 */
public class EHESTypeListModel extends AbstractCreateDataTypeModel {

	public static final String DATA_TYPE_NAME = "ESTypeList";
	private static final String STRUCTURE_NAME = STRUCT_PREFIX + DATA_TYPE_NAME;

	private static final int COUNT_ORDINAL = 0;
	private static final int TYPE_ARRAY_ORDINAL = 1;

	private DataType dataType;

	/**
	 * Creates the model for the exception handling ESTypeList data type.
	 * @param program the program
	 * @param esTypeListAddress the address in the program for the ESTypeList data type.
	 */
	public EHESTypeListModel(Program program, Address esTypeListAddress,
			DataValidationOptions validationOptions) {
		super(program, 1, esTypeListAddress, validationOptions);
	}

	@Override
	public String getName() {
		return DATA_TYPE_NAME;
	}

	/**
	 * Whether or not the memory at the indicated address appears to be a valid location for the
	 * indicated number of ESTypeList data types.
	 * @throws InvalidDataTypeException if this model's location does not appear to be a valid 
	 * group of ESTypeList entries. The exception has a message indicating
	 * why it does not appear to be a valid location for the data type.
	 */
	@Override
	protected void validateModelSpecificInfo() throws InvalidDataTypeException {
		int handlerTypeCount = getHandlerTypeCount();
		Address handlerTypeMapAddress = getHandlerTypeMapAddress();
		// Does the handler type map have a count and address.
		if (handlerTypeCount == 0 || handlerTypeMapAddress == null ||
			(isRelative() && imageBaseAddress.equals(handlerTypeMapAddress))) {
			throw new InvalidDataTypeException(getName() + " data type doesn't have any map data.");
		}
		// Are the pointers or displacements to valid addresses.
		if (!isValidMap(getHandlerTypeCount(), getHandlerTypeMapAddress())) {
			throw new InvalidDataTypeException(getName() + " data type at " + getAddress() +
				" doesn't have a valid handler type map.");
		}
	}

	/**
	 * This gets the ESTypeList structure for the indicated program.
	 * @param program the program which will contain this data type. 
	 * @return the ESTypeList structure.
	 */
	public static DataType getDataType(Program program) {

		DataTypeManager dataTypeManager = program.getDataTypeManager();
		boolean isRelative = isRelative(program);
		CategoryPath categoryPath = new CategoryPath(CATEGORY_PATH);
		StructureDataType struct =
			getAlignedPack4Structure(dataTypeManager, categoryPath, STRUCTURE_NAME);

		// Add the components.
		DataType compDt;

		/* comps[0] */
		compDt = new IntegerDataType(dataTypeManager);
		struct.add(compDt, "nCount", null);

		/* comps[1] */
		if (isRelative) {
			compDt = new ImageBaseOffset32DataType(dataTypeManager);
			struct.add(compDt, "dispTypeArray", null);
		}
		else {
			compDt = new PointerDataType(EHCatchHandlerModel.getDataType(program), dataTypeManager);
			struct.add(compDt, "pTypeArray", null);
		}

		TypedefDataType typeDefDt =
			new TypedefDataType(categoryPath, DATA_TYPE_NAME, struct, dataTypeManager);

		return MSDataTypeUtils.getMatchingDataType(program, typeDefDt);
	}

	/**
	 * This gets the ESTypeList structure for this model.
	 * @return the ESTypeList structure.
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
		return getDataType().getLength();
	}

	/**
	 * Gets the catch handler model for the catch handler address in the ESTypeList.
	 * @return the catch handler model, which may be invalid.
	 * @throws InvalidDataTypeException if valid ESTypeList data can't be created at the model's address.
	 */
	public EHCatchHandlerModel getCatchHandlerModel() throws InvalidDataTypeException {
		checkValidity();
		EHCatchHandlerModel catchHandlerModel = new EHCatchHandlerModel(getProgram(),
			getHandlerTypeCount(), getHandlerTypeMapAddress(), validationOptions);
		return catchHandlerModel;
	}

	/**
	 * Gets the handler type entry count, if there is one, for this ESTypeList.
	 * @return the catch handler type count
	 * @throws InvalidDataTypeException if valid ESTypeList data can't be created at the model's address.
	 */
	public int getHandlerTypeCount() throws InvalidDataTypeException {
		checkValidity();
		// component 0 is number of catch handler type list records
		return EHDataTypeUtilities.getCount(getDataType(), COUNT_ORDINAL, getMemBuffer());
	}

	/**
	 * Gets the address of the handler type map, if there is one. Otherwise, this returns null.
	 * @return the address of the handler type map or null.
	 * @throws InvalidDataTypeException if valid ESTypeList data can't be created at the model's address.
	 */
	public Address getHandlerTypeMapAddress() throws InvalidDataTypeException {
		checkValidity();
		// component 1 is catch handler type list pointer or displacement.
		Address mapAddress =
			EHDataTypeUtilities.getAddress(getDataType(), TYPE_ARRAY_ORDINAL, getMemBuffer());
		return getAdjustedAddress(mapAddress, getHandlerTypeCount());
	}

	/**
	 * Gets the address of the component containing the address of the handler type map, 
	 * if there is one. Otherwise, this returns null.
	 * @return the address of the component with the address of the handler type map or null.
	 * @throws InvalidDataTypeException if valid ESTypeList data can't be created at the model's address.
	 */
	public Address getComponentAddressOfHandlerTypeMapAddress() throws InvalidDataTypeException {
		checkValidity();
		// component 1 is catch handler type list pointer or displacement.
		return EHDataTypeUtilities.getComponentAddress(getDataType(), TYPE_ARRAY_ORDINAL,
			getMemBuffer());
	}
}
