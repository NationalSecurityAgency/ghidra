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
 * Model for exception handling information about the UnwindMapEntry data type and its 
 * associated exception handling data types.
 * <br>
 * This is based on data type information from ehdata.h
 */
public class EHUnwindModel extends AbstractCreateDataTypeModel {

	public static final String DATA_TYPE_NAME = "UnwindMapEntry";
	private static String STRUCTURE_NAME = STRUCT_PREFIX + DATA_TYPE_NAME;

	private static final int TO_STATE_ORDINAL = 0;
	private static final int ACTION_ORDINAL = 1;

	private DataType dataType;

	/**
	 * Creates the model for the exception handling TryBlockMapEntry data type.
	 * @param program the program
	 * @param unwindCount the number of UnwindMapEntry data types expected at the map address.
	 * @param unwindMapAddress the address in the program for the map of UnwindMapEntry data
	 * types.
	 */
	public EHUnwindModel(Program program, int unwindCount, Address unwindMapAddress,
			DataValidationOptions validationOptions) {
		super(program, unwindCount, unwindMapAddress, validationOptions);
	}

	@Override
	public String getName() {
		return DATA_TYPE_NAME;
	}

	/**
	 * Whether or not the memory at the indicated address appears to be a valid location for the
	 * indicated number of unwind map entry data types.
	 * @throws InvalidDataTypeException if this model's location does not appear to be a valid 
	 * group of unwind map entries. The exception has a message indicating
	 * why it does not appear to be a valid location for the data type.
	 */
	@Override
	protected void validateModelSpecificInfo() throws InvalidDataTypeException {
		// Does each unwind map entry refer to a valid action?
		Program program = getProgram();
		int numEntries = getCount();
		for (int unwindBlockOrdinal = 0; unwindBlockOrdinal < numEntries; unwindBlockOrdinal++) {
			Address actionAddress = getActionAddress(unwindBlockOrdinal);
			if ((actionAddress != null) &&
				!EHDataTypeUtilities.isValidForFunction(program, actionAddress)) {
				throw new InvalidDataTypeException(getName() + " data type at " + getAddress() +
					" doesn't refer to a valid location for an action.");
			}
		}
	}

	/**
	 * This gets the UnwindMapEntry structure for the indicated program.
	 * @param program the program which will contain this data type. 
	 * @return the UnwindMapEntry structure.
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
		DataType ehStateDt = MSDataTypeUtils.getEHStateDataType(program);
		if (ehStateDt == null) {
			ehStateDt = new IntegerDataType(dataTypeManager);
		}
		struct.add(ehStateDt, "toState", null);

		/* comps[1] */
		if (isRelative) {
			compDt = new ImageBaseOffset32DataType(dataTypeManager);
		}
		else {

			FunctionDefinitionDataType functionDefDt = new FunctionDefinitionDataType(
				new CategoryPath("/ehdata.h/functions"), "action", dataTypeManager);
			functionDefDt.setReturnType(new VoidDataType(dataTypeManager));
			compDt = new PointerDataType(functionDefDt, dataTypeManager);
		}
		struct.add(compDt, "action", null);

		TypedefDataType typedefDt =
			new TypedefDataType(categoryPath, DATA_TYPE_NAME, struct, dataTypeManager);

		return MSDataTypeUtils.getMatchingDataType(program, typedefDt);
	}

	/**
	 * This gets the UnwindMapEntry structure for this model.
	 * @return the UnwindMapEntry structure.
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
	 * Gets the To State value of the unwind, if there is one, in the UnwindMapEntry indicated 
	 * by the ordinal.
	 * @param unwindOrdinal 0-based ordinal indicating which UnwindMapEntry in the map.
	 * @return the To State value of the unwind
	 * @throws InvalidDataTypeException if valid UnwindMapEntry data can't be created for 
	 * the indicated ordinal.
	 */
	public int getToState(int unwindOrdinal) throws InvalidDataTypeException {
		checkValidity(unwindOrdinal);
		DataType dt = getDataType();
		MemBuffer specificMemBuffer = getSpecificMemBuffer(unwindOrdinal, dt);
		// component 0 is the To State for this unwind entry.
		return EHDataTypeUtilities.getEHStateValue(dt, TO_STATE_ORDINAL, specificMemBuffer);
	}

	/**
	 * Gets the unwind action address, if there is one, in the UnwindMapEntry 
	 * indicated by the ordinal.
	 * @param unwindOrdinal 0-based ordinal indicating which UnwindMapEntry in the map.
	 * @return the unwind action address or null.
	 * @throws InvalidDataTypeException if valid UnwindMapEntry data can't be created for 
	 * the indicated ordinal.
	 */
	public Address getActionAddress(int unwindOrdinal) throws InvalidDataTypeException {
		checkValidity(unwindOrdinal);
		DataType unwindDt = getDataType();
		MemBuffer specificMemBuffer = getSpecificMemBuffer(unwindOrdinal, unwindDt);
		// component 1 is action pointer or displacement.
		Address refAddress =
			EHDataTypeUtilities.getAddress(unwindDt, ACTION_ORDINAL, specificMemBuffer);
		return getAdjustedAddress(refAddress, 0);
	}

	/**
	 * Gets the address of the component containing the unwind action address, if there is one. 
	 * Otherwise, this returns null.
	 * @param unwindOrdinal 0-based ordinal indicating which UnwindMapEntry in the map.
	 * @return the address of the component with the unwind action address or null.
	 * @throws InvalidDataTypeException if valid UnwindMapEntry data can't be created for 
	 * the indicated ordinal.
	 */
	public Address getComponentAddressOfActionAddress(int unwindOrdinal)
			throws InvalidDataTypeException {
		checkValidity(unwindOrdinal);
		DataType dt = getDataType();
		MemBuffer specificMemBuffer = getSpecificMemBuffer(unwindOrdinal, dt);
		// component 1 is action pointer or displacement.
		return EHDataTypeUtilities.getComponentAddress(dt, ACTION_ORDINAL, specificMemBuffer);
	}
}
