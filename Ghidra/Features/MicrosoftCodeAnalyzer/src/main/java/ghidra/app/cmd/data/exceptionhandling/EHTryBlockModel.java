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
import ghidra.program.model.mem.MemBuffer;

/**
 * Model for exception handling information about the TryBlockMapEntry data type and its 
 * associated exception handling data types.
 * <br>
 * This is based on data type information from ehdata.h
 */
public class EHTryBlockModel extends AbstractCreateDataTypeModel {

	public static String DATA_TYPE_NAME = "TryBlockMapEntry";
	private static String STRUCTURE_NAME = STRUCT_PREFIX + DATA_TYPE_NAME;

	private static final int TRY_LOW_ORDINAL = 0;
	private static final int TRY_HIGH_ORDINAL = 1;
	private static final int CATCH_HIGH_ORDINAL = 2;
	private static final int CATCH_COUNT_ORDINAL = 3;
	private static final int HANDLER_ARRAY_ORDINAL = 4;

	private DataType dataType;

	/**
	 * Creates the model for the exception handling TryBlockMapEntry data type.
	 * @param program the program
	 * @param tryBlockCount the number of TryBlockMapEntry data types expected at the map address.
	 * @param tryBlockMapAddress the address in the program for the map of TryBlockMapEntry data
	 * types.
	 */
	public EHTryBlockModel(Program program, int tryBlockCount, Address tryBlockMapAddress,
			DataValidationOptions validationOptions) {
		super(program, tryBlockCount, tryBlockMapAddress, validationOptions);
	}

	@Override
	public String getName() {
		return DATA_TYPE_NAME;
	}

	/**
	 * Whether or not the memory at the indicated address appears to be a valid location for the
	 * indicated number of try block map entry data types.
	 * @throws InvalidDataTypeException if this model's location does not appear to be a valid 
	 * group of try block map entries. The exception has a message indicating
	 * why it does not appear to be a valid location for the data type.
	 */
	@Override
	protected void validateModelSpecificInfo() throws InvalidDataTypeException {
		// Does each try map entry have a valid catch handler?
		int numEntries = getCount();
		for (int tryBlockOrdinal = 0; tryBlockOrdinal < numEntries; tryBlockOrdinal++) {
			if (!isValidMap(getCatchHandlerCount(tryBlockOrdinal),
				getCatchHandlerMapAddress(tryBlockOrdinal))) {
				throw new InvalidDataTypeException(getName() + " data type at " + getAddress() +
					" doesn't have a valid catch handler map.");
			}
		}
	}

	/**
	 * This gets the TryBlockMapEntry structure for the indicated program.
	 * @param program the program which will contain this data type. 
	 * @return the TryBlockMapEntry structure.
	 */
	public static DataType getDataType(Program program) {

		DataTypeManager dataTypeManager = program.getDataTypeManager();
		boolean isRelative = isRelative(program);
		CategoryPath categoryPath = new CategoryPath(CATEGORY_PATH);
		StructureDataType struct =
			getAlignedPack4Structure(dataTypeManager, categoryPath, STRUCTURE_NAME);
		DataType ehStateDt = MSDataTypeUtils.getEHStateDataType(program);

		// Add the components.
		DataType compDt;

		/* comps[0] */
		struct.add(ehStateDt, "tryLow", null);

		/* comps[1] */
		struct.add(ehStateDt, "tryHigh", null);

		/* comps[2] */
		struct.add(ehStateDt, "catchHigh", null);

		/* comps[3] */
		compDt = new IntegerDataType(dataTypeManager);
		struct.add(compDt, "nCatches", null);

		/* comps[4] */
		if (isRelative) {
			compDt = new ImageBaseOffset32DataType(dataTypeManager);
			struct.add(compDt, "dispHandlerArray", null);
		}
		else {
			compDt = new PointerDataType(EHCatchHandlerModel.getDataType(program), dataTypeManager);
			struct.add(compDt, "pHandlerArray", null);
		}

		TypedefDataType typedefDt =
			new TypedefDataType(categoryPath, DATA_TYPE_NAME, struct, dataTypeManager);

		return MSDataTypeUtils.getMatchingDataType(program, typedefDt);
	}

	/**
	 * This gets the TryBlockMapEntry structure for this model.
	 * @return the TryBlockMapEntry structure.
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
	 * Gets the low state value of the try, if there is one, in the TryBlockMapEntry indicated 
	 * by the ordinal.
	 * @param tryBlockOrdinal 0-based ordinal indicating which TryBlockMapEntry in the map.
	 * @return the low state value of the try
	 * @throws InvalidDataTypeException 
	 */
	public int getTryLow(int tryBlockOrdinal) throws InvalidDataTypeException {
		checkValidity(tryBlockOrdinal);
		DataType dt = getDataType();
		MemBuffer specificMemBuffer = getSpecificMemBuffer(tryBlockOrdinal, dt);
		// component 0 is the low state value of the try
		return EHDataTypeUtilities.getEHStateValue(dt, TRY_LOW_ORDINAL, specificMemBuffer);
	}

	/**
	 * Gets the high state value of the try, if there is one, in the TryBlockMapEntry indicated 
	 * by the ordinal.
	 * @param tryBlockOrdinal 0-based ordinal indicating which TryBlockMapEntry in the map.
	 * @return the high state value of the try
	 * @throws InvalidDataTypeException if valid TryBlockMapEntry data can't be created for 
	 * the indicated ordinal.
	 */
	public int getTryHigh(int tryBlockOrdinal) throws InvalidDataTypeException {
		checkValidity(tryBlockOrdinal);
		DataType dt = getDataType();
		MemBuffer specificMemBuffer = getSpecificMemBuffer(tryBlockOrdinal, dt);
		// component 1 is the high state value of the try
		return EHDataTypeUtilities.getEHStateValue(dt, TRY_HIGH_ORDINAL, specificMemBuffer);
	}

	/**
	 * Gets the high state value of the catches, if there is one, in the TryBlockMapEntry indicated 
	 * by the ordinal.
	 * @param tryBlockOrdinal 0-based ordinal indicating which TryBlockMapEntry in the map.
	 * @return the high state value of the catches
	 * @throws InvalidDataTypeException if valid TryBlockMapEntry data can't be created for 
	 * the indicated ordinal.
	 */
	public int getCatchHigh(int tryBlockOrdinal) throws InvalidDataTypeException {
		checkValidity(tryBlockOrdinal);
		DataType dt = getDataType();
		MemBuffer specificMemBuffer = getSpecificMemBuffer(tryBlockOrdinal, dt);
		// component 2 is the high state value of the catches
		return EHDataTypeUtilities.getEHStateValue(dt, CATCH_HIGH_ORDINAL, specificMemBuffer);
	}

	/**
	 * Gets the catch handler model for the catch handler address in the 
	 * TryBlockMapEntry indicated by the ordinal.
	 * @param tryBlockOrdinal 0-based ordinal indicating which TryBlockMapEntry in the map.
	 * @return the catch handler model, which may be invalid.
	 * @throws InvalidDataTypeException if valid TryBlockMapEntry data can't be created for 
	 * the indicated ordinal.
	 */
	public EHCatchHandlerModel getCatchHandlerModel(int tryBlockOrdinal)
			throws InvalidDataTypeException {
		checkValidity();
		EHCatchHandlerModel catchHandlerModel =
			new EHCatchHandlerModel(getProgram(), getCatchHandlerCount(tryBlockOrdinal),
				getCatchHandlerMapAddress(tryBlockOrdinal), validationOptions);
		return catchHandlerModel;
	}

	/**
	 * Gets the catch handler map's entry count, if there is one, in the TryBlockMapEntry 
	 * indicated by the ordinal.
	 * @param tryBlockOrdinal 0-based ordinal indicating which TryBlockMapEntry in the map.
	 * @return the catch handler count
	 * @throws InvalidDataTypeException if valid TryBlockMapEntry data can't be created for 
	 * the indicated ordinal.
	 */
	public int getCatchHandlerCount(int tryBlockOrdinal) throws InvalidDataTypeException {
		checkValidity(tryBlockOrdinal);
		DataType dt = getDataType();
		MemBuffer specificMemBuffer = getSpecificMemBuffer(tryBlockOrdinal, dt);
		// component 3 is number of catch handler records
		return EHDataTypeUtilities.getCount(dt, CATCH_COUNT_ORDINAL, specificMemBuffer);
	}

	/**
	 * Gets the catch handler map's address, if there is one, in the TryBlockMapEntry 
	 * indicated by the ordinal.
	 * @param tryBlockOrdinal 0-based ordinal indicating which TryBlockMapEntry in the map.
	 * @return the catch handler map's address
	 * @throws InvalidDataTypeException if valid TryBlockMapEntry data can't be created for 
	 * the indicated ordinal.
	 */
	public Address getCatchHandlerMapAddress(int tryBlockOrdinal) throws InvalidDataTypeException {
		checkValidity(tryBlockOrdinal);
		DataType dt = getDataType();
		MemBuffer specificMemBuffer = getSpecificMemBuffer(tryBlockOrdinal, dt);
		// component 4 is action pointer or displacement.
		Address mapAddress =
			EHDataTypeUtilities.getAddress(dt, HANDLER_ARRAY_ORDINAL, specificMemBuffer);
		return getAdjustedAddress(mapAddress, getCatchHandlerCount(tryBlockOrdinal));
	}

	/**
	 * Gets the component address of the catch handler map's address, if there is one, in the 
	 * TryBlockMapEntry indicated by the ordinal.
	 * @param tryBlockOrdinal 0-based ordinal indicating which TryBlockMapEntry in the map.
	 * @return the address of the component with the catch handler map's address
	 * @throws InvalidDataTypeException if valid TryBlockMapEntry data can't be created for 
	 * the indicated ordinal.
	 */
	public Address getComponentAddressOfCatchHandlerMapAddress(int tryBlockOrdinal)
			throws InvalidDataTypeException {
		checkValidity(tryBlockOrdinal);
		DataType dt = getDataType();
		MemBuffer specificMemBuffer = getSpecificMemBuffer(tryBlockOrdinal, dt);
		// component 4 is action pointer or displacement.
		return EHDataTypeUtilities.getComponentAddress(dt, HANDLER_ARRAY_ORDINAL,
			specificMemBuffer);
	}
}
