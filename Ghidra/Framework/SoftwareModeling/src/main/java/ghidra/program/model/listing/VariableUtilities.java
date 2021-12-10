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
package ghidra.program.model.listing;

import java.util.*;

import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

public class VariableUtilities {

	private static int PARAMETER_PRECEDENCE = 10;

	private static int UNIQUE_PRECEDENCE = 16;
	private static int MEMORY_PRECEDENCE = 15;
	private static int STACK_PRECEDENCE = 14;
	private static int REGISTER_PRECEDENCE = 13;
	private static int COMPOUND_PRECEDENCE = 11;

	private VariableUtilities() {
	}

	/**
	 * Get a precedence value for the specified variable.
	 * This value can be used to assist with LocalVariable.compareTo(Variable var)
	 * @param var
	 * @return numeric precedence
	 */
	public static int getPrecedence(Variable var) {
		int precedence;
		if (var.isMemoryVariable()) {
			precedence = MEMORY_PRECEDENCE;
		}
		else if (var.isRegisterVariable()) {
			precedence = REGISTER_PRECEDENCE;
		}
		else if (var.isStackVariable()) {
			precedence = STACK_PRECEDENCE;
		}
		else if (var.isUniqueVariable()) {
			precedence = UNIQUE_PRECEDENCE;
		}
		else if (var.isCompoundVariable()) {
			precedence = COMPOUND_PRECEDENCE;
		}
		else {
			precedence = 0;
		}
		if (var instanceof Parameter) {
			precedence -= PARAMETER_PRECEDENCE;
		}
		return precedence;
	}

	/**
	 * Compare storage varnodes for two lists of variables.  No check is done to ensure that
	 * storage is considered good/valid (i.e., BAD_STORAGE, UNASSIGNED_STORAGE and VOID_STORAGE
	 * all have an empty varnode list and would be considered a match)
	 * @param vars
	 * @param otherVars
	 * @return true if the exact sequence of variable storage varnodes matches across two lists of variables.
	 */
	public static boolean storageMatches(List<Variable> vars, List<Variable> otherVars) {
		if (otherVars.size() != vars.size()) {
			return false;
		}
		for (int i = 0; i < otherVars.size(); i++) {
			if (!otherVars.get(i).getVariableStorage().equals(vars.get(i).getVariableStorage())) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Compare storage varnodes for two lists of variables.  No check is done to ensure that
	 * storage is considered good/valid (i.e., BAD_STORAGE, UNASSIGNED_STORAGE and VOID_STORAGE
	 * all have an empty varnode list and would be considered a match)
	 * @param vars
	 * @param otherVars
	 * @return true if the exact sequence of variable storage varnodes matches across two lists of variables.
	 */
	public static boolean storageMatches(List<? extends Variable> vars, Variable... otherVars) {
		if (otherVars.length != vars.size()) {
			return false;
		}
		for (int i = 0; i < otherVars.length; i++) {
			VariableStorage storage = vars.get(i).getVariableStorage();
			VariableStorage otherStorage = otherVars[i].getVariableStorage();
			if (!Arrays.equals(storage.getVarnodes(), otherStorage.getVarnodes())) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Compare two variables without using the instance specific compareTo method.
	 * @param v1
	 * @param v2
	 * @return a negative value if v1 &lt; v2, 0 if equal, and
	 * positive if v1 &gt; v2
	 */
	public static int compare(Variable v1, Variable v2) {

		if ((v1 instanceof Parameter) && (v2 instanceof Parameter)) {
			// All dynamic/unmapped variables should be parameters
			return ((Parameter) v1).getOrdinal() - ((Parameter) v2).getOrdinal();
		}
		int diff = getPrecedence(v1) - getPrecedence(v2);
		if (diff != 0) {
			return diff;
		}
		//
		VariableStorage otherStorage = v2.getVariableStorage();
		VariableStorage variableStorage = v1.getVariableStorage();

		// null storage should never occur

		if (v1.isStackVariable() && v2.isStackVariable()) {
			// For some reason we like to reverse the natural order of stack variable addresses
			diff = v2.getStackOffset() - v1.getStackOffset();
			if (diff != 0) {
				return diff;
			}
		}

		diff = v1.getFirstUseOffset() - v2.getFirstUseOffset();
		if (diff != 0) {
			// give precedence to 0 first-use-offset
			if (v1.getFirstUseOffset() == 0) {
				return -1;
			}
			if (v2.getFirstUseOffset() == 0) {
				return 1;
			}
			return diff;
		}

		return variableStorage.compareTo(otherStorage);
	}

	/**
	 * Determine the appropriate data type for an automatic parameter
	 * @param function
	 * @param returnDataType
	 * @param storage variable storage for an auto-parameter (isAutoStorage should be true)
	 * @return auto-parameter data type
	 */
	public static DataType getAutoDataType(Function function, DataType returnDataType,
			VariableStorage storage) {

		AutoParameterType autoParameterType = storage.getAutoParameterType();
		if (autoParameterType == AutoParameterType.THIS) {
			DataType classStruct = findOrCreateClassStruct(function);
			if (classStruct == null) {
				classStruct = DataType.VOID;
			}
			return getPointer(function.getProgram(), classStruct, storage.size());
		}
		else if (autoParameterType == AutoParameterType.RETURN_STORAGE_PTR) {
			return getPointer(function.getProgram(), returnDataType, storage.size());
		}
		return Undefined.getUndefinedDataType(storage.size());
	}

	private static Pointer getPointer(Program program, DataType baseType, int ptrSize) {
		DataTypeManager dtMgr = program.getDataTypeManager();
		if (program.getDefaultPointerSize() == ptrSize) {
			return dtMgr.getPointer(baseType);
		}
		return dtMgr.getPointer(baseType, ptrSize);
	}

	/**
	 * Perform variable storage checks using the specified datatype.
	 * @param storage variable storage whose size must match the specified data type size
	 * @param dataType a datatype checked using {@link #checkDataType(DataType, boolean, int, Program)}
	 * @param allowSizeMismatch if true size mismatch will be ignore
	 * @throws InvalidInputException
	 */
	public static void checkStorage(VariableStorage storage, DataType dataType,
			boolean allowSizeMismatch) throws InvalidInputException {
		checkStorage(null, storage, dataType, allowSizeMismatch);
	}

	/**
	 * Perform variable storage checks using the specified datatype.
	 * @param function if specified and variable storage size does not match the data-type size
	 * an attempt will be made to resize the specified storage.
	 * @param storage variable storage
	 * @param dataType a datatype checked using {@link #checkDataType(DataType, boolean, int, Program)}
	 * @param allowSizeMismatch if true size mismatch will be ignore
	 * @return original storage or resized storage with the correct size.
	 * @throws InvalidInputException
	 */
	public static VariableStorage checkStorage(Function function, VariableStorage storage,
			DataType dataType, boolean allowSizeMismatch) throws InvalidInputException {
		if (!storage.isValid()) {
			return storage; // allow BAD and UNASSIGNED to pass thru
		}
		DataType baseType = dataType;
		if (baseType instanceof TypeDef) {
			baseType = ((TypeDef) baseType).getBaseDataType();
		}
		int storageSize = storage.size();
		int dtLen = dataType.getLength();
		if (baseType instanceof VoidDataType) {
			storage = VariableStorage.VOID_STORAGE;
		}
		else if (storage.isUniqueStorage() || storage.isConstantStorage()) {
			throw new InvalidInputException("Invalid storage address specified: " + storage);
		}
		else if (dtLen == 0 && (baseType instanceof Structure)) {
			storage = VariableStorage.UNASSIGNED_STORAGE;
		}
		else if (!allowSizeMismatch && storageSize != dtLen) {
			if (dataType instanceof AbstractFloatDataType) {
				return storage;  // do not constrain or attempt resize of float storage
			}
			if (function != null) {
				return resizeStorage(storage, dataType, true, function);
			}
			if (dtLen < storageSize && storage.isRegisterStorage()) {
				// TODO: this could be expanded to handle other storage
				return new VariableStorage(storage.getProgram(),
					shrinkRegister(storage.getRegister(), storageSize - dtLen));
			}
			throw new InvalidInputException(
				"Storage size does not match data type size: " + dataType.getLength());
		}
		return storage;
	}

	/**
	 * Check the specified datatype for use as a return, parameter or variable type.  It may
	 * not be suitable for other uses.  The following datatypes will be mutated into a default pointer datatype:
	 * <ul>
	 * <li>Function definition datatype</li>
	 * <li>An unsized/zero-element array</li>
	 * </ul>
	 * @param dataType datatype to be checked
	 * @param voidOK true if checking return datatype and void is allow, else false.
	 * @param defaultSize Undefined datatype size to be used if specified datatype is null.  A value less than 1
	 * will result in the DEFAULT data type being returned (i.e., "undefined").
	 * @param dtMgr target datatype manager (null permitted which will adopt default data organization)
	 * @return cloned/mutated datatype suitable for function parameters and variables (including function return data type).
	 * @throws InvalidInputException if an unacceptable datatype was specified
	 */
	public static DataType checkDataType(DataType dataType, boolean voidOK, int defaultSize,
			DataTypeManager dtMgr) throws InvalidInputException {

		if (dataType == null) {
			dataType = Undefined.getUndefinedDataType(defaultSize);
		}
		else if (dataType instanceof BitFieldDataType) {
			throw new InvalidInputException("Bitfield not permitted");
		}
		else if (dataType instanceof Dynamic || dataType instanceof FactoryDataType) {
			throw new InvalidInputException(
				"Dynamic and Factory data types are not permitted: " + dataType.getName());
		}

		DataType baseType = dataType;
		if (baseType instanceof TypeDef) {
			baseType = ((TypeDef) baseType).getBaseDataType();
		}

		if (baseType instanceof FunctionDefinition) {
			dataType = new PointerDataType(dataType, dtMgr);
		}
		else if (baseType instanceof Array) {
			// TODO: Uncertain if typedefs or multi-dimensional arrays should be handled?
			Array a = (Array) baseType;
			if (a.getNumElements() == 0) {
				// convert unsized/zero-length array to pointer
				dataType = new PointerDataType(a.getDataType(), dtMgr);
			}
		}

		// A clone is done to ensure that any affects of the data organization
		// are properly reflected in the sizing of the datatype.
		// NOTE: This will not properly handle composites since a deep-clone is not performed.
		dataType = dataType.clone(dtMgr);

		if (baseType instanceof VoidDataType) {
			if (!voidOK) {
				throw new InvalidInputException(
					"The void type is not permitted - allowed for function return use only");
			}
			return dataType;
		}

		if (dataType.getLength() <= 0) {
			// Unexpected condition - only dynamic types are expected to have negative length and
			// none should report 0 has a length.
			throw new IllegalArgumentException("Unsupported data type length (" +
				dataType.getLength() + "): " + dataType.getName());
		}
		return dataType;
	}

	/**
	 * Check the specified datatype for use as a return, parameter or variable type.  It may
	 * not be suitable for other uses.  The following datatypes will be mutated into a default pointer datatype:
	 * <ul>
	 * <li>Function definition datatype</li>
	 * <li>An unsized/zero-element array</li>
	 * </ul>
	 * @param dataType datatype to be checked
	 * @param voidOK true if checking return datatype and void is allow, else false.
	 * @param defaultSize Undefined datatype size to be used if specified datatype is null.  A value less than 1
	 * will result in the DEFAULT data type being returned (i.e., "undefined").
	 * @param program target program
	 * @return cloned/mutated datatype suitable for function parameters and variables (including function return data type).
	 * @throws InvalidInputException if an unacceptable datatype was specified
	 */
	public static DataType checkDataType(DataType dataType, boolean voidOK, int defaultSize,
			Program program) throws InvalidInputException {
		return checkDataType(dataType, voidOK, defaultSize, program.getDataTypeManager());
	}

	/**
	 * Check the specified datatype for use as a return, parameter or variable type.  It may
	 * not be suitable for other uses.  The following datatypes will be mutated into a default pointer datatype:
	 * <ul>
	 * <li>Function definition datatype</li>
	 * <li>An unsized/zero-element array</li>
	 * </ul>
	 * @param dataType datatype to be checked.  If null is specified the DEFAULT datatype will be
	 * returned.
	 * @param voidOK true if checking return datatype and void is allow, else false.
	 * @param dtMgr target datatype manager (null permitted which will adopt default data organization)
	 * @return cloned/mutated datatype suitable for function parameters and variables (including function return data type).
	 * @throws InvalidInputException if an unacceptable datatype was specified
	 */
	public static DataType checkDataType(DataType dataType, boolean voidOK, DataTypeManager dtMgr)
			throws InvalidInputException {
		return checkDataType(dataType, voidOK, -1, dtMgr);
	}

	/**
	 * Perform resize variable storage to desired newSize.  This method has limited ability to grow
	 * storage if current storage does not have a stack component or if other space constraints
	 * are exceeded.
	 * @param curStorage
	 * @param dataType
	 * @param alignStack if false no attempt is made to align stack usage for big-endian
	 * @param function
	 * @return resize storage
	 * @throws InvalidInputException if unable to resize storage to specified size.
	 */
	public static VariableStorage resizeStorage(VariableStorage curStorage, DataType dataType,
			boolean alignStack, Function function) throws InvalidInputException {
		if (!curStorage.isValid()) {
			return curStorage;
		}
		int newSize = dataType.getLength();
		int curSize = curStorage.size();
		if (curSize == newSize) {
			return curStorage;
		}
		if (curSize == 0 || curStorage.isUniqueStorage() || curStorage.isHashStorage()) {
			throw new InvalidInputException("Storage can't be resized: " + curStorage.toString());
		}

		if (dataType instanceof TypeDef) {
			dataType = ((TypeDef) dataType).getBaseDataType();
		}
		if (dataType instanceof AbstractFloatDataType) {
			return curStorage; // do not constrain or attempt resize of float storage
		}

		if (newSize > curSize) {
			return expandStorage(curStorage, newSize, dataType, alignStack, function);
		}
		return shrinkStorage(curStorage, newSize, dataType, alignStack, function);
	}

	private static VariableStorage shrinkStorage(VariableStorage curStorage, int newSize,
			DataType dataType, boolean alignStack, Function function) throws InvalidInputException {
		Program program = function.getProgram();
		List<Varnode> newList = new ArrayList<>();
		int size = 0;
		for (Varnode vn : curStorage.getVarnodes()) {
			size += vn.getSize();
			if (size >= newSize) {
				newList.add(shrinkVarnode(vn, size - newSize, curStorage, newSize, dataType,
					alignStack, function));
				break;
			}
			newList.add(vn);
		}
		return new VariableStorage(program, newList);
	}

	private static VariableStorage expandStorage(VariableStorage curStorage, int newSize,
			DataType dataType, boolean alignStack, Function function) throws InvalidInputException {
		Program program = function.getProgram();
		Varnode[] varnodes = curStorage.getVarnodes();
		int lastIndex = varnodes.length - 1;
		varnodes[lastIndex] = expandVarnode(varnodes[lastIndex], newSize - curStorage.size(),
			curStorage, newSize, dataType, alignStack, function);
		return new VariableStorage(program, varnodes);
	}

	private static Varnode shrinkVarnode(Varnode varnode, int sizeReduction,
			VariableStorage curStorage, int newSize, DataType dataType, boolean alignStack,
			Function function) throws InvalidInputException {
		Address addr = varnode.getAddress();
		if (addr.isStackAddress()) {
			return resizeStackVarnode(varnode, varnode.getSize() - sizeReduction, curStorage,
				newSize, dataType, alignStack, function);
		}
		boolean isRegister = function.getProgram().getRegister(varnode) != null;
		boolean bigEndian = function.getProgram().getMemory().isBigEndian();
		boolean complexDt = (dataType instanceof Composite) || (dataType instanceof Array);
		if (bigEndian && (isRegister || !complexDt)) {
			return new Varnode(varnode.getAddress().add(sizeReduction),
				varnode.getSize() - sizeReduction);
		}
		return new Varnode(varnode.getAddress(), varnode.getSize() - sizeReduction);
	}

	private static Varnode shrinkRegister(Register reg, int sizeReduction) {
		boolean bigEndian = reg.isBigEndian();
		if (bigEndian) {
			return new Varnode(reg.getAddress().add(sizeReduction),
				reg.getMinimumByteSize() - sizeReduction);
		}
		return new Varnode(reg.getAddress(), reg.getMinimumByteSize() - sizeReduction);
	}

	private static Varnode expandVarnode(Varnode varnode, int sizeIncrease,
			VariableStorage curStorage, int newSize, DataType dataType, boolean alignStack,
			Function function) throws InvalidInputException {

		Address addr = varnode.getAddress();
		if (addr.isStackAddress()) {
			return resizeStackVarnode(varnode, varnode.getSize() + sizeIncrease, curStorage,
				newSize, dataType, alignStack, function);
		}
		int size = varnode.getSize() + sizeIncrease;
		boolean bigEndian = function.getProgram().getMemory().isBigEndian();
		Register reg = function.getProgram().getRegister(varnode);
		Address vnAddr = varnode.getAddress();
		if (reg != null) {
			// Register expansion
			Register newReg = reg;
			while ((newReg.getMinimumByteSize() < size)) {
				newReg = newReg.getParentRegister();
				if (newReg == null) {
					throw new InvalidInputException("Storage can't be expanded to " + newSize +
						" bytes: " + curStorage.toString());
				}
			}

			vnAddr = newReg.getAddress();
			if (bigEndian) {
				vnAddr = vnAddr.add(newReg.getMinimumByteSize() - size);
				return new Varnode(vnAddr, size);
			}
		}
		boolean complexDt = (dataType instanceof Composite) || (dataType instanceof Array);
		if (bigEndian && !complexDt) {
			return new Varnode(vnAddr.subtract(sizeIncrease), size);
		}
		return new Varnode(vnAddr, size);
	}

	private static Varnode resizeStackVarnode(Varnode varnode, int newVarnodeSize,
			VariableStorage curStorage, int newSize, DataType dataType, boolean align,
			Function function) throws InvalidInputException {

		boolean complexDt = (dataType instanceof Composite) || (dataType instanceof Array);

		StackAttributes stackAttributes = getStackAttributes(function);

		Address curAddr = varnode.getAddress();
		int stackOffset = (int) curAddr.getOffset();
		int newStackOffset = stackOffset;

		if (stackAttributes.rightJustify && align) {

			// complex data-type: always left align
			// simple data-type: right align within minimum number of aligned cells

			int stackAlign = stackAttributes.stackAlign;

			if ((stackOffset + varnode.getSize() - stackAttributes.bias) % stackAlign != 0) {
				stackAlign = 1; // was not aligned to start with
			}

			int newAlign = (newStackOffset - stackAttributes.bias) % stackAlign;
			if (newAlign < 0) {
				newAlign += stackAlign;
			}
			newStackOffset -= newAlign;	// left-alignment of start offset
			if (!complexDt) {
				// right-align non-complex data
				int cellExcess = newVarnodeSize % stackAlign;
				if (cellExcess != 0) {
					newStackOffset += stackAlign - cellExcess;
				}
			}
		}

		int newEndStackOffset = newStackOffset + newVarnodeSize - 1;
		if (newStackOffset < 0 && newEndStackOffset >= 0) {
			throw new InvalidInputException(
				"Data type does not fit within variable stack constraints");
		}

		return new Varnode(curAddr.getNewAddress(newStackOffset), newVarnodeSize);
	}

	private static class StackAttributes {

		final int stackAlign;
		final int bias;
		final boolean rightJustify; // only applies to primitives

		public StackAttributes(int stackAlign, int bias, boolean rightJustify) {
			this.stackAlign = stackAlign;
			this.bias = bias;
			this.rightJustify = rightJustify;
		}
	}

	private static StackAttributes getStackAttributes(Function function) {
		CompilerSpec compilerSpec = function.getProgram().getCompilerSpec();
		boolean rightJustify = compilerSpec.isStackRightJustified();
		// stack is right-justified with negative offset
		PrototypeModel callingConvention = function.getCallingConvention();
		if (callingConvention == null) {
			callingConvention = compilerSpec.getDefaultCallingConvention();
		}
		int stackAlign = callingConvention.getStackParameterAlignment();
		if (stackAlign < 0) {
			stackAlign = 1;
		}
		int bias = 0;
		Long stackBase = callingConvention.getStackParameterOffset();
		if (stackBase != null) {
			bias = (int) (stackBase.longValue() % stackAlign);
			if (bias < 0) {
				bias += stackAlign;
			}
		}
		return new StackAttributes(stackAlign, bias, rightJustify);
	}

	/**
	 * Check for variable storage conflict and optionally remove conflicting variables.
	 * @param function
	 * @param var existing function variable or null for new variable
	 * @param newStorage new/updated variable storage
	 * @param deleteConflictingVariables
	 * @throws VariableSizeException if deleteConflictingVariables is false and another variable conflicts
	 */
	public static void checkVariableConflict(Function function, Variable var,
			VariableStorage newStorage, boolean deleteConflictingVariables)
			throws VariableSizeException {
		if (!newStorage.isValid()) {
			return;
		}
		List<Variable> conflicts = null;
		for (Variable otherVar : function.getAllVariables()) {
			if (otherVar.equals(var)) {
				// skip variable being modified
				continue;
			}
			if (var != null && otherVar.getFirstUseOffset() != var.getFirstUseOffset()) {
				// other than parameters we will have a hard time identifying
				// local variable conflicts due to differences in scope (i.e., first-use)
				continue;
			}
			if (otherVar.getVariableStorage().intersects(newStorage)) {
				if (deleteConflictingVariables) {
					function.removeVariable(otherVar);
				}
				else {
					if (conflicts == null) {
						conflicts = new ArrayList<>();
					}
					conflicts.add(otherVar);
				}
			}
		}

		if (conflicts != null) {
			generateConflictException(newStorage, conflicts, 4);
		}
	}

	/**
	 * Check for variable storage conflict and optionally remove conflicting variables.
	 * @param existingVariables variables to check (may contain null entries)
	 * @param var
	 * @param newStorage
	 * @throws VariableSizeException
	 * @throws VariableSizeException if another variable conflicts
	 */
	public static void checkVariableConflict(List<? extends Variable> existingVariables,
			Variable var, VariableStorage newStorage, VariableConflictHandler conflictHandler)
			throws VariableSizeException {
		if (!newStorage.isValid()) {
			return;
		}
		List<Variable> conflicts = null;
		for (Variable otherVar : existingVariables) {
			if (otherVar == null || otherVar.equals(var)) {
				// skip variable being modified
				continue;
			}
			if (var != null && otherVar.getFirstUseOffset() != var.getFirstUseOffset()) {
				// other than parameters we will have a hard time identifying
				// local variable conflicts due to differences in scope (i.e., first-use)
				continue;
			}
			if (otherVar.getVariableStorage().intersects(newStorage)) {
				if (conflicts == null) {
					conflicts = new ArrayList<>();
				}
				conflicts.add(otherVar);
			}
		}

		if (conflicts != null) {
			if (conflictHandler == null || !conflictHandler.resolveConflicts(conflicts)) {
				generateConflictException(newStorage, conflicts, 4);
			}
		}
	}

	public interface VariableConflictHandler {
		/**
		 * Provides means of resolving variable conflicts (e.g., removing of conflicts)
		 * @param conflicts variable conflicts
		 * @return true if conflicts resolved else false
		 */
		boolean resolveConflicts(List<Variable> conflicts);
	}

	private static void generateConflictException(VariableStorage newStorage,
			List<Variable> conflicts, int maxConflictVarDetails) throws VariableSizeException {

		maxConflictVarDetails = Math.min(conflicts.size(), maxConflictVarDetails);

		StringBuffer msg = new StringBuffer();
		msg.append("Variable storage conflict between " + newStorage + " and: ");
		for (int i = 0; i < maxConflictVarDetails; i++) {
			if (i != 0) {
				msg.append(", ");
			}
			msg.append(conflicts.get(i).getVariableStorage().toString());
		}
		if (maxConflictVarDetails < conflicts.size()) {
			msg.append(" ... {");
			msg.append(Integer.toString(conflicts.size() - maxConflictVarDetails));
			msg.append(" more}");
		}
		throw new VariableSizeException(msg.toString(), true);
	}

	/**
	 * Determine the minimum stack offset for parameters
	 * @param function
	 * @return stack parameter offset or null if it could not be determined
	 */
	public static Integer getBaseStackParamOffset(Function function) {
		PrototypeModel convention = function.getCallingConvention();
		if (convention == null) {
			convention = function.getProgram().getCompilerSpec().getDefaultCallingConvention();
		}

		// If we have conventions, try to figure out where the parameters do start
		//   if no conventions or stack parameter defs, assume 0
		//
		Integer baseOffset = null;
		if (convention != null) {
			Long val = convention.getStackParameterOffset();
			if (val == null) {
				baseOffset = convention.getStackshift();
			}
			else {
				baseOffset = val.intValue();
			}
		}
		return baseOffset;
	}

	/**
	 * Generate a suitable 'this' parameter for the specified function
	 * @param function
	 * @return this parameter or null of calling convention is not a 'thiscall'
	 * or some other error prevents it
	 * @deprecated should rely on auto-param instead - try not to use this method which may be eliminated
	 */
	@Deprecated
	public static ParameterImpl getThisParameter(Function function, PrototypeModel convention) {
		if (convention != null &&
			convention.getGenericCallingConvention() == GenericCallingConvention.thiscall) {

			DataType dt = findOrCreateClassStruct(function);
			if (dt == null) {
				dt = DataType.VOID;
			}
			dt = new PointerDataType(dt);
			DataType[] arr = new DataType[2];
			arr[0] = DataType.VOID;
			arr[1] = dt;
			VariableStorage thisStorage =
				convention.getStorageLocations(function.getProgram(), arr, true)[1];
			try {
				return new ParameterImpl("this", 0, dt, thisStorage, false, function.getProgram(),
					SourceType.ANALYSIS);
			}
			catch (InvalidInputException e) {
				Msg.error(VariableUtilities.class,
					"Error while generating 'this' parameter for function at " +
						function.getEntryPoint() + ": " + e.getMessage());
			}
		}
		return null;
	}

	/**
	 * Create an empty placeholder class structure whose category is derived from
	 * the function's class namespace.  NOTE: The structure will not be added to the data
	 * type manager.
	 * @param classNamespace class namespace
	 * @param dataTypeManager data type manager's whose data organization should be applied.
	 * @return new class structure
	 */
	private static Structure createPlaceholderClassStruct(GhidraClass classNamespace,
			DataTypeManager dataTypeManager) {

		Namespace classParentNamespace = classNamespace.getParentNamespace();
		CategoryPath category =
			DataTypeUtilities.getDataTypeCategoryPath(CategoryPath.ROOT, classParentNamespace);

		StructureDataType structDT =
			new StructureDataType(category, classNamespace.getName(), 0, dataTypeManager);
		structDT.setDescription("PlaceHolder Class Structure");
		return structDT;
	}

	/**
	 * Find the structure data type which corresponds to the specified class namespace
	 * within the specified data type manager.
	 * The preferred structure will utilize a namespace-based category path, however,
	 * the match criteria can be fuzzy and relies primarily on the class name.
	 * While a new empty structure may be returned, it will not be added to the program's data type
	 * manager.
	 * @param classNamespace class namespace
	 * @param dataTypeManager data type manager which should be searched and whose
	 * data organization should be used.
	 * @return new or existing structure whose name matches the specified class namespace
	 */
	public static Structure findOrCreateClassStruct(GhidraClass classNamespace,
			DataTypeManager dataTypeManager) {
		Structure struct = findExistingClassStruct(classNamespace, dataTypeManager);
		if (struct == null) {
			struct = createPlaceholderClassStruct(classNamespace, dataTypeManager);
		}
		return struct;
	}

	/**
	 * Find the structure data type which corresponds to the specified function's class namespace
	 * within the function's program.  One will be instantiated if not found.
	 * The preferred structure will utilize a namespace-based category path, however,
	 * the match criteria can be fuzzy and relies primarily on the class name.
	 * @param function function's whose class namespace is the basis for the structure
	 * @return new or existing structure whose name matches the function's class namespace or
	 * null if function not contained within a class namespace.
	 */
	public static Structure findOrCreateClassStruct(Function function) {
		Namespace namespace = function.getParentNamespace();
		if (!(namespace instanceof GhidraClass)) {
			return null;
		}
		return findOrCreateClassStruct((GhidraClass) namespace,
			function.getProgram().getDataTypeManager());
	}

	/**
	 * Find the structure data type which corresponds to the specified class namespace
	 * within the specified data type manager. .
	 * The preferred structure will utilize a namespace-based category path, however,
	 * the match criteria can be fuzzy and relies primarily on the class name.
	 * @param classNamespace class namespace
	 * @param dataTypeManager data type manager which should be searched.
	 * @return existing structure whose name matches the specified class namespace
	 * or null if not found.
	 */
	public static Structure findExistingClassStruct(GhidraClass classNamespace,
			DataTypeManager dataTypeManager) {
		return (Structure) DataTypeUtilities.findDataType(dataTypeManager,
			classNamespace.getParentNamespace(), classNamespace.getName(), Structure.class);
	}

	/**
	 * Find the structure data type which corresponds to the specified function's class namespace
	 * within the function's program.
	 * The preferred structure will utilize a namespace-based category path, however,
	 * the match criteria can be fuzzy and relies primarily on the class name.
	 * @param func the function.
	 * @return existing structure whose name matches the specified function's class namespace
	 * or null if not found.
	 */
	public static Structure findExistingClassStruct(Function func) {
		Namespace namespace = func.getParentNamespace();
		if (!(namespace instanceof GhidraClass)) {
			return null;
		}
		return findExistingClassStruct((GhidraClass) namespace,
			func.getProgram().getDataTypeManager());
	}

	public static boolean equivalentVariableArrays(Variable[] vars1, Variable[] vars2) {
		if (vars1 == vars2) {
			return true;
		}
		if (vars1 == null || vars2 == null) {
			return false;
		}

		int length = vars1.length;
		if (vars2.length != length) {
			return false;
		}

		for (int i = 0; i < length; i++) {
			if (!(vars1[i] == null ? vars2[i] == null : equivalentVariables(vars1[i], vars2[i]))) {
				return false;
			}
		}

		return true;
	}

	public static boolean equivalentVariables(Variable var1, Variable var2) {
		String comment1 = var1.getComment();
		String comment2 = var2.getComment();
		return var1.equals(var2) && var1.getName().equals(var2.getName()) &&
			var1.getDataType().isEquivalent(var2.getDataType()) &&
			((comment1 == null) ? (comment2 == null) : comment1.equals(comment2));
	}

}
