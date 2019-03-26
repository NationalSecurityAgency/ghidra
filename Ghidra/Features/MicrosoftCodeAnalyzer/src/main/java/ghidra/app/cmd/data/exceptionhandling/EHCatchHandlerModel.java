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

import ghidra.app.cmd.data.*;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.util.datatype.microsoft.MSDataTypeUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.exception.AssertException;

/**
 * Model for exception handling information about the HandlerType data type and its 
 * associated exception handling data types.
 * <br>
 * This is based on data type information from ehdata.h
 */
public class EHCatchHandlerModel extends AbstractCreateDataTypeModel {

	public static final String DATA_TYPE_NAME = "HandlerType";
	private static String STRUCTURE_NAME = STRUCT_PREFIX + DATA_TYPE_NAME;

	private static final int ADJECTIVES_ORDINAL = 0;
	private static final int TYPE_DESCRIPTOR_ORDINAL = 1;
	private static final int CATCH_OBJECT_ORDINAL = 2;
	private static final int HANDLER_ORDINAL = 3;
	private static final int FUNCTION_FRAME_ORDINAL = 4;

	private DataType dataType;

	/**
	 * Creates the model for the exception handling HandlerType data type.
	 * @param program the program
	 * @param catchHandlerCount the number of HandlerType data types expected at the map address.
	 * @param catchHandlerMapAddress the address in the program for the map of HandlerType data
	 * types.
	 */
	public EHCatchHandlerModel(Program program, int catchHandlerCount,
			Address catchHandlerMapAddress, DataValidationOptions validationOptions) {
		super(program, catchHandlerCount, catchHandlerMapAddress, validationOptions);
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
		// Does each catch handler map entry refer to a valid catch handler and type descriptor?
		Program program = getProgram();
		int numEntries = getCount();
		for (int catchHandlerOrdinal = 0; catchHandlerOrdinal < numEntries; catchHandlerOrdinal++) {
			Address catchHandlerAddress = getCatchHandlerAddress(catchHandlerOrdinal);
			if (catchHandlerAddress == null ||
				!EHDataTypeUtilities.isValidForFunction(program, catchHandlerAddress)) {
				throw new InvalidDataTypeException(getName() + " data type at " + getAddress() +
					" doesn't refer to a valid location for a catch handler for entry " +
					catchHandlerOrdinal + ".");
			}
			Address typeDescriptorAddress = getTypeDescriptorAddress(catchHandlerOrdinal);
			if (typeDescriptorAddress != null &&
				!EHDataTypeUtilities.isValidAddress(program, typeDescriptorAddress)) {
				throw new InvalidDataTypeException(getName() + " data type at " + getAddress() +
					" doesn't refer to a valid location for the type descriptor for entry " +
					catchHandlerOrdinal + ".");
			}
		}
	}

	/**
	 * This gets the HandlerType structure for the indicated program.
	 * @param program the program which will contain this data type. 
	 * @return the HandlerType structure.
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
		compDt = new UnsignedIntegerDataType(dataTypeManager);
		struct.add(compDt, "adjectives", null);

		/* comps[1] */
		if (isRelative) {
			compDt = new ImageBaseOffset32DataType(dataTypeManager);
			struct.add(compDt, "dispType", null);
		}
		else {
			compDt = new PointerDataType(TypeDescriptorModel.getDataType(program), dataTypeManager);
			struct.add(compDt, "pType", null);
		}

		/* comps[2] */
		if (isRelative) {
			compDt = new IntegerDataType(dataTypeManager);
		}
		else {
			compDt = new TypedefDataType(new CategoryPath("/crtdefs.h"), "ptrdiff_t",
				new IntegerDataType(dataTypeManager), dataTypeManager);
		}
		struct.add(compDt, "dispCatchObj", null);

		/* comps[3] */
		if (isRelative) {
			compDt = new ImageBaseOffset32DataType(dataTypeManager);
			struct.add(compDt, "dispOfHandler", null);
		}
		else {
			compDt = new PointerDataType(new VoidDataType(dataTypeManager), dataTypeManager);
			struct.add(compDt, "addressOfHandler", null);
		}

		// Only some 64 bit programs have this displacement of the address of the function frame.
		/* comps[4] */
		if (isRelative) { // Needs more checking here still. Incorrectly puts it in all 64 bit programs.
			compDt = new DWordDataType(dataTypeManager);
			struct.add(compDt, "dispFrame", null);
		}

		TypedefDataType typeDefDt =
			new TypedefDataType(categoryPath, DATA_TYPE_NAME, struct, dataTypeManager);

		return MSDataTypeUtils.getMatchingDataType(program, typeDefDt);
	}

	/**
	 * This gets the HandlerType structure for this model.
	 * @return the HandlerType structure.
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
	 * Gets the type descriptor model for the type descriptor address in the 
	 * HandlerType entry indicated by the ordinal.
	 * @param catchHandlerOrdinal 0-based ordinal indicating which HandlerType entry in the map.
	 * @return the model for the type descriptor, if there is one.
	 * @throws InvalidDataTypeException if valid HandlerType data can't be created for 
	 * the indicated ordinal.
	 */
	public TypeDescriptorModel getTypeDescriptorModel(int catchHandlerOrdinal)
			throws InvalidDataTypeException {
		checkValidity(catchHandlerOrdinal);
		Address typeDescriptorAddress = getTypeDescriptorAddress(catchHandlerOrdinal);
		if (typeDescriptorAddress != null) {
			return new TypeDescriptorModel(getProgram(), typeDescriptorAddress, validationOptions);
		}
		return null;
	}

	/**
	 * Gets the address, if there is one, of the type descriptor address in the 
	 * HandlerType entry indicated by the ordinal. Otherwise, this returns null.
	 * @param catchHandlerOrdinal 0-based ordinal indicating which HandlerType entry in the map.
	 * @return the address of the type descriptor or null.
	 * @throws InvalidDataTypeException if valid HandlerType data can't be created for 
	 * the indicated ordinal.
	 */
	public Address getTypeDescriptorAddress(int catchHandlerOrdinal)
			throws InvalidDataTypeException {
		checkValidity(catchHandlerOrdinal);
		DataType catchHandlerDt = getDataType();
		MemBuffer specificMemBuffer = getSpecificMemBuffer(catchHandlerOrdinal, catchHandlerDt);
		// component 1 is action pointer or displacement.
		Address refAddress = EHDataTypeUtilities.getAddress(catchHandlerDt, TYPE_DESCRIPTOR_ORDINAL,
			specificMemBuffer);
		return getAdjustedAddress(refAddress, 0);
	}

	/**
	 * Gets the address, if there is one, of the component with the type descriptor address in the 
	 * HandlerType entry indicated by the ordinal. Otherwise, this returns null.
	 * @param catchHandlerOrdinal 0-based ordinal indicating which HandlerType entry in the map.
	 * @return the address of the component with the type descriptor address or null.
	 * @throws InvalidDataTypeException if valid HandlerType data can't be created for 
	 * the indicated ordinal.
	 */
	public Address getComponentAddressOfTypeDescriptorAddress(int catchHandlerOrdinal)
			throws InvalidDataTypeException {
		checkValidity(catchHandlerOrdinal);
		DataType catchHandlerDt = getDataType();
		MemBuffer specificMemBuffer = getSpecificMemBuffer(catchHandlerOrdinal, catchHandlerDt);
		// component 1 is action pointer or displacement.
		return EHDataTypeUtilities.getComponentAddress(catchHandlerDt, TYPE_DESCRIPTOR_ORDINAL,
			specificMemBuffer);
	}

	/**
	 * Gets the address of the catch handler in the map as indicated by the ordinal, if there is one. 
	 * Otherwise, this returns null.
	 * @param catchHandlerOrdinal 0-based ordinal indicating which HandlerType entry in the map.
	 * @return the address of the catch handler within the indicated HandlerType entry in the 
	 * map or null.
	 * @throws InvalidDataTypeException if valid HandlerType data can't be created for 
	 * the indicated ordinal.
	 */
	public Address getCatchHandlerAddress(int catchHandlerOrdinal) throws InvalidDataTypeException {
		checkValidity(catchHandlerOrdinal);
		DataType catchHandlerDt = getDataType();
		MemBuffer specificMemBuffer = getSpecificMemBuffer(catchHandlerOrdinal, catchHandlerDt);
		// component 3 is handler pointer or displacement.
		Address refAddress =
			EHDataTypeUtilities.getAddress(catchHandlerDt, HANDLER_ORDINAL, specificMemBuffer);
		return getAdjustedAddress(refAddress, 0);
	}

	/**
	 * Gets the address, if there is one, of the component with the catch handler address in the 
	 * HandlerType entry indicated by the ordinal. Otherwise, this returns null.
	 * @return the address of the component with the catch handler address or null.
	 * @throws InvalidDataTypeException if valid HandlerType data can't be created for 
	 * the indicated ordinal.
	 */
	public Address getComponentAddressOfCatchHandlerAddress(int catchHandlerOrdinal)
			throws InvalidDataTypeException {
		checkValidity(catchHandlerOrdinal);
		DataType dt = getDataType();
		MemBuffer specificMemBuffer = getSpecificMemBuffer(catchHandlerOrdinal, dt);
		// component 3 is handler pointer or displacement.
		return EHDataTypeUtilities.getComponentAddress(dt, HANDLER_ORDINAL, specificMemBuffer);
	}

	/**
	 * Gets a modifier that provides information about specific modifications for the catch
	 * handler type in the indicated HandlerType map entry.
	 * @param catchHandlerOrdinal 0-based ordinal indicating which HandlerType entry in the map.
	 * @return the modifier information for the catch handler type or NO_MODIFIERS if they 
	 * can't be determined.
	 * @throws InvalidDataTypeException if valid HandlerType data can't be created for 
	 * the indicated ordinal.
	 */
	public EHCatchHandlerTypeModifier getModifiers(int catchHandlerOrdinal)
			throws InvalidDataTypeException {
		checkValidity(catchHandlerOrdinal);
		DataType dt = getDataType();
		if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}
		Structure struct = (Structure) dt; // We know this from getDataType().
		DataTypeComponent component = struct.getComponent(ADJECTIVES_ORDINAL);
		int offset = component.getOffset();
		MemBuffer specificMemBuffer = getSpecificMemBuffer(catchHandlerOrdinal, dt);
		try {
			// adjectives are at start of catch handler memory buffer.
			int modifiers = specificMemBuffer.getInt(offset); // Can throw MemoryAccessException
			return new EHCatchHandlerTypeModifier(modifiers);
		}
		catch (MemoryAccessException e) {
			throw new AssertException(e); // Shouldn't happen; checkValidity() would have failed above.
		}
	}

	/**
	 * Gets a name for the catch handler function based on its type descriptor or whether it is a 
	 * catch all. The name will be for the HandlerType in the map that is indicated by the ordinal.
	 * @param catchHandlerOrdinal 0-based ordinal indicating which HandlerType entry in the map.
	 * @return the name for the catch handler function.
	 * @throws InvalidDataTypeException if valid HandlerType data can't be created for 
	 * the indicated ordinal.
	 */
	public String getCatchHandlerName(int catchHandlerOrdinal) throws InvalidDataTypeException {
		String name = "Catch";
		DataType dt = getDataType();
		if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}
		if (!(dt instanceof Structure)) {
			return name;
		}
		// Commented out the following until we can get the demangled type name to use in the catch function name.
//		String typeName = null;
//		Address typeDescriptorAddress = getTypeDescriptorAddress(catchHandlerOrdinal);
//		if (typeDescriptorAddress != null) {
//			typeName = getTypeName(catchHandlerOrdinal);
//		}
//		if (typeName != null) {
//			name += "_" + typeName;
//		}
//		else {
		EHCatchHandlerTypeModifier modifiers = getModifiers(catchHandlerOrdinal);
		if (modifiers.isAllCatch()) {
			name += "_All";
		}
//		}
		return name;
	}

	// Commented out the following until we can get the demangled type name to use in the catch function name.
//	private String getTypeName(int catchHandlerOrdinal) throws InvalidDataTypeException {
//		TypeDescriptorModel typeDescriptorModel = getTypeDescriptorModel(catchHandlerOrdinal);
//		String typeName = typeDescriptorModel.getTypeName();
//		if (typeName != null) {
//			// Try to demangle the name.
//			// Option 1
//			DemangledObject demangledObject = DemanglerUtil.demangle(getProgram(), typeName);
//			if (demangledObject != null) {
//				String demangledTypeName = demangledObject.getName();
//				if (demangledTypeName != null && !typeName.equals(demangledTypeName)) {
//					typeName = demangledTypeName;
//				}
//			}
////			// Option 2
////			DemanglerCmd demanglerCmd = new DemanglerCmd(typeNameAddress, typeName);
////			boolean success = demanglerCmd.applyTo(program);
////			if (success) {
////				String demangledTypeName = demanglerCmd.getResult();
////				if (demangledTypeName != null && !typeName.equals(demangledTypeName)) {
////					typeName = demangledTypeName;
////				}
////			}
//		}
//		return typeName;
//	}

	/**
	 * Gets the scalar for the catch object displacement in the indicated HandlerType map entry.
	 * @param catchHandlerOrdinal 0-based ordinal indicating which HandlerType entry in the map.
	 * @return the scalar for the catch object displacement.
	 * @throws InvalidDataTypeException if valid HandlerType data can't be created for 
	 * the indicated ordinal.
	 */
	public Scalar getCatchObjectDisplacement(int catchHandlerOrdinal)
			throws InvalidDataTypeException {
		checkValidity(catchHandlerOrdinal);
		DataType catchHandlerDt = getDataType();
		MemBuffer specificMemBuffer = getSpecificMemBuffer(catchHandlerOrdinal, catchHandlerDt);
		// component 2 is displacement of catch object.
		// component is an int or typedef on an int.
		return EHDataTypeUtilities.getScalarValue(catchHandlerDt, CATCH_OBJECT_ORDINAL,
			specificMemBuffer);
	}

	/**
	 * Gets the scalar for the displacement of the address of the function frame in the 
	 * indicated HandlerType map entry.
	 * @param catchHandlerOrdinal 0-based ordinal indicating which HandlerType entry in the map.
	 * @return scalar for the displacement of the address of the function frame.
	 * @throws InvalidDataTypeException if valid HandlerType data can't be created for 
	 * the indicated ordinal.
	 */
	public Scalar getFunctionFrameAddressDisplacement(int catchHandlerOrdinal)
			throws InvalidDataTypeException {
		checkValidity(catchHandlerOrdinal);
		DataType catchHandlerDt = getDataType();
		MemBuffer specificMemBuffer = getSpecificMemBuffer(catchHandlerOrdinal, catchHandlerDt);
		// component 4 is the displacement of the address of function frame.
		// Component is a dword.
		return EHDataTypeUtilities.getScalarValue(catchHandlerDt, FUNCTION_FRAME_ORDINAL,
			specificMemBuffer);
	}
}
