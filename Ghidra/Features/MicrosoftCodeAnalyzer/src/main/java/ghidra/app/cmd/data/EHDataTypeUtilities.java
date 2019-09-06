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
package ghidra.app.cmd.data;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.datatype.microsoft.DataApplyOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

/**
 * This class provides static utility methods for use with the exception handling models and
 * data types.
 */
public class EHDataTypeUtilities {

	private EHDataTypeUtilities() {
		// utility class; can't create
	}

	/**
	 * If the indicated component in the data type exists and is an ehstate value, this returns
	 * the integer value contained in that component of the data type.
	 * @param dataType the data type whose base type is a structure and whose component's
	 * integer value is wanted.
	 * @param componentOrdinal 0-based ordinal indicating the component whose integer value is being
	 * determined by this method.
	 * @param memBuffer memory buffer that starts where the indicated data type is laid down.
	 * @return the integer value held by indicated component in the data type when laid down on
	 * the specified memory. If the value can't be determined, 0 is returned.
	 */
	public static int getEHStateValue(DataType dataType, int componentOrdinal,
			MemBuffer memBuffer) {
		return getIntegerValue(dataType, componentOrdinal, memBuffer);
	}

	/**
	 * If the indicated component in the data type exists and is a count value, this returns
	 * the integer value contained in that component of the data type.
	 * @param dataType the data type whose base type is a structure and whose component's
	 * integer value is wanted. (i.e., The component data type referenced by the ordinal value must
	 * be one that returns a Scalar value; such as an IntegerDataType, EnumDataType,
	 * UndefinedDataType, etc.)
	 * @param componentOrdinal 0-based ordinal indicating the component whose integer value is being
	 * determined by this method.
	 * @param memBuffer memory buffer that starts where the indicated data type is laid down.
	 * @return the integer value held by indicated component in the data type when laid down on
	 * the specified memory. If the value can't be determined, 0 is returned.
	 */
	public static int getCount(DataType dataType, int componentOrdinal, MemBuffer memBuffer) {
		return getIntegerValue(dataType, componentOrdinal, memBuffer);
	}

	/**
	 * If the indicated component in the data type exists and is an integer value, this returns
	 * the integer value contained in that component of the data type.
	 * @param dataType the data type whose base type is a structure and whose component's
	 * integer value is wanted. (i.e., The component data type referenced by the ordinal value must
	 * be one that returns a Scalar value; such as an IntegerDataType, EnumDataType,
	 * UndefinedDataType, etc.)
	 * @param componentOrdinal 0-based ordinal indicating the component whose integer value is being
	 * determined by this method.
	 * @param memBuffer memory buffer that starts where the indicated data type is laid down.
	 * @return the integer value held by indicated component in the data type when laid down on
	 * the specified memory.
	 */
	public static int getIntegerValue(DataType dataType, int componentOrdinal,
			MemBuffer memBuffer) {
		Scalar scalar = getScalarValue(dataType, componentOrdinal, memBuffer);
		return (int) scalar.getValue();
	}

	/**
	 * If the indicated component in the data type exists and is a Scalar value, this returns
	 * the scalar value contained in that component of the data type.
	 * @param dataType the data type whose base type is a structure and whose component's
	 * scalar value is wanted. (i.e., The component data type referenced by the ordinal value must
	 * be one that returns a Scalar value; such as an IntegerDataType, EnumDataType,
	 * UndefinedDataType, etc.)
	 * @param componentOrdinal 0-based ordinal indicating the component whose scalar value is being
	 * determined by this method.
	 * @param memBuffer memory buffer that starts where the indicated data type is laid down.
	 * @return the scalar value held by indicated component in the data type when laid down on
	 * the specified memory.
	 */
	public static Scalar getScalarValue(DataType dataType, int componentOrdinal,
			MemBuffer memBuffer) {
		DataTypeComponent comp = getComponent(dataType, componentOrdinal, memBuffer);
		if (comp == null) {
			throw new IllegalArgumentException("Couldn't get component " + componentOrdinal +
				" of " + dataType.getName() + " @ " + memBuffer.getAddress() + ".");
		}
		Address compAddress = getComponentAddress(comp, memBuffer);
		DataType compDt = comp.getDataType();
		int length = comp.getLength();
		DumbMemBufferImpl compMemBuffer = new DumbMemBufferImpl(memBuffer.getMemory(), compAddress);
		Object value = compDt.getValue(compMemBuffer, comp.getDefaultSettings(), length);
		if (value instanceof Scalar) {
			return (Scalar) value;
		}
		throw new IllegalArgumentException(
			"Component " + componentOrdinal + " of " + dataType.getName() + " is a " +
				compDt.getName() + " data type, which doesn't produce a Scalar value.");
	}

	private static Address getComponentAddress(DataTypeComponent comp, MemBuffer memBuffer) {
		int offset = comp.getOffset();
		Address minAddress = memBuffer.getAddress();
		try {
			return minAddress.add(offset);
		}
		catch (AddressOutOfBoundsException e) {
			throw new IllegalArgumentException("Can't get component " + comp.getOrdinal() +
				" from memory buffer for data type " + comp.getParent().getName() + ".", e);
		}
	}

	private static DataTypeComponent getComponent(DataType dataType, int componentOrdinal,
			MemBuffer memBuffer) {
		if (dataType == null) {
			throw new IllegalArgumentException("Data type cannot be null.");
		}
		if (dataType instanceof DynamicDataType) {
			DynamicDataType dynamicDt = (DynamicDataType) dataType;
			return dynamicDt.getComponent(componentOrdinal, memBuffer);
		}
		if (dataType instanceof TypeDef) {
			dataType = ((TypeDef) dataType).getBaseDataType();
		}
		if (!(dataType instanceof Structure)) {
			throw new IllegalArgumentException("Data type " + dataType.getName() +
				" must be a structure or a typedef on a structure.");
		}
		Structure struct = (Structure) dataType;
		return struct.getComponent(componentOrdinal);
	}

	/**
	 * If the indicated component in the data type exists and is an absolute or relative value that
	 * equates to an address, this returns the address indicated by that component of the data type.
	 * @param dataType the data type whose base type is a structure and whose component's
	 * address value is wanted. (i.e., The component data type referenced by the ordinal value
	 * must be one that returns an Address value; such as a PointerDataType or
	 * ImageBaseOffset32DataType)
	 * @param componentOrdinal 0-based ordinal indicating the component whose address value is being
	 * determined by this method.
	 * @param memBuffer memory buffer that starts where the indicated data type is laid down.
	 * @return the address value held by indicated component in the data type when laid down on
	 * the specified memory or null if component is not used (i.e., value == 0).
	 */
	public static Address getAddress(DataType dataType, int componentOrdinal, MemBuffer memBuffer) {
		DataTypeComponent comp = getComponent(dataType, componentOrdinal, memBuffer);
		if (comp == null) {
			throw new IllegalArgumentException("Couldn't get component " + componentOrdinal +
				" of " + dataType.getName() + " @ " + memBuffer.getAddress() + ".");
		}
		Address compAddress = getComponentAddress(comp, memBuffer);
		DataType compDt = comp.getDataType();
		int length = comp.getLength();
		DumbMemBufferImpl compMemBuffer = new DumbMemBufferImpl(memBuffer.getMemory(), compAddress);
		Object value = compDt.getValue(compMemBuffer, comp.getDefaultSettings(), length);
		if (value == null) {
			return null;
		}
		if (value instanceof Address) {
			return (Address) value;
		}
		throw new IllegalArgumentException(
			"Component " + componentOrdinal + " of " + dataType.getName() + " is a " +
				compDt.getName() + " data type, which doesn't produce an Address value.");
	}

	/**
	 * Gets the address of the indicated component in the data type that is placed in a program
	 * at the indicated memory buffer. If the specified address can't be determined then
	 * null is returned.
	 * @param dataType the data type whose base type is a structure and whose component's
	 * address is wanted.
	 * @param componentOrdinal 0-based ordinal indicating the component whose address is being
	 * determined by this method.
	 * @param memBuffer memory buffer that starts where the indicated data type is laid down.
	 * @return the component address or null.
	 */
	public static Address getComponentAddress(DataType dataType, int componentOrdinal,
			MemBuffer memBuffer) {
		DataTypeComponent comp = getComponent(dataType, componentOrdinal, memBuffer);
		if (comp == null) {
			throw new IllegalArgumentException("Couldn't get component " + componentOrdinal +
				" of " + dataType.getName() + " @ " + memBuffer.getAddress() + ".");
		}
		return getComponentAddress(comp, memBuffer);
	}

	/**
	 * Creates a comment if it doesn't already exist at the specified address in the program
	 * and if it doesn't contain the <code>dataTypeName</code> string. 
	 * The comment will contain the prefix, the <code>dataTypeName</code>, and the suffix. 
	 * If a comment already exists without containing the dataTypeName, 
	 * then this comment will be appended to the existing one.
	 * 
	 * @param program the program.
	 * @param prefix the prefix string that precedes the dataTypeName
	 * @param dataTypeName the name for the data type at the indicated address.
	 * @param suffix the suffix that follows the dataTypeName
	 * @param address the address where the plate comment should be created in the program.
	 * @param applyOptions options indicating whether or not to apply comments.
	 * 
	 * @return the comment or null.
	 */
	public static String createPlateCommentIfNeeded(Program program, String prefix,
			String dataTypeName, String suffix, Address address, DataApplyOptions applyOptions) {

		Listing listing = program.getListing();
		String existingComment = listing.getComment(CodeUnit.PLATE_COMMENT, address);
		if (!applyOptions.shouldCreateComments()) {
			return existingComment;
		}
		if (dataTypeName != null) {
			if (existingComment != null && existingComment.contains(dataTypeName)) {
				return existingComment;
			}
			String appliedPrefix = (prefix != null) ? (prefix) : "";
			String appliedSuffix = (suffix != null) ? (suffix) : "";
			String appliedExisting = (existingComment != null) ? (existingComment + "\n") : "";
			String appliedComment = appliedExisting + appliedPrefix + dataTypeName + appliedSuffix;
			listing.setComment(address, CodeUnit.PLATE_COMMENT, appliedComment);
			return appliedComment;
		}
		return existingComment;
	}

	/**
	 * Creates a symbol if one containing the <code>dataTypeName</code> doesn't already exist at 
	 * the specified address in the program.
	 * 
	 * @param program the program.
	 * @param prefix the symbol prefix to be used in the symbol name.
	 * @param dataTypeName the dataTypeName to be used in the symbol name.
	 * @param suffix the symbol suffix to be used in the symbol name.
	 * @param address the address where the symbol should be created in the program.
	 * @param applyOptions options indicating whether or not to apply comments.
	 * 
	 * @return the symbol or null.
	 * 
	 * @throws InvalidInputException thrown if symbol can't be created as specified.
	 */
	public static Symbol createSymbolIfNeeded(Program program, String prefix, String dataTypeName,
			String suffix, Address address, DataApplyOptions applyOptions)
			throws InvalidInputException {

		if (dataTypeName == null || !applyOptions.shouldCreateLabel()) {
			return null;
		}

		// Make sure we have underscores in name
		dataTypeName = SymbolUtilities.replaceInvalidChars(dataTypeName, true);

		SymbolTable symbolTable = program.getSymbolTable();
		Symbol[] symbols = symbolTable.getSymbols(address);
		for (Symbol symbol : symbols) {
			if (symbol.getName().contains(dataTypeName)) {
				return null; // Already have one with dataTypeName.
			}
		}

		String appliedPrefix = (prefix != null) ? (prefix) : "";
		String appliedSuffix = (suffix != null) ? (suffix) : "";
		String appliedSymbol = appliedPrefix + dataTypeName + appliedSuffix;
		appliedSymbol = SymbolUtilities.replaceInvalidChars(appliedSymbol, true);

		return symbolTable.createLabel(address, appliedSymbol, SourceType.ANALYSIS);
	}

	/**
	 * Creates a symbol if it doesn't already exist at the specified address in the program
	 * by adding an underscore and the address to the symbolPrefix string that is passed to it.
	 * @param program the program.
	 * @param symbolPrefix the symbol prefix to be used in the symbol name.
	 * @param symbolAddress the address where the symbol should be created in the program.
	 * @return the symbol or null.
	 * @throws InvalidInputException thrown if symbol can't be created as specified.
	 */
	public static Symbol createSymbolIfNeeded(Program program, String symbolPrefix,
			Address symbolAddress) throws InvalidInputException {
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol primarySymbol = symbolTable.getPrimarySymbol(symbolAddress);
		if (primarySymbol != null && primarySymbol.getSource() != SourceType.DEFAULT) {
			return null; // Not needed. Non-default symbol already there.
		}
		String addressAppendedName =
			SymbolUtilities.getAddressAppendedName(symbolPrefix, symbolAddress);
		return symbolTable.createLabel(symbolAddress, addressAppendedName, SourceType.ANALYSIS);
	}

	/**
	 * Creates a function at the specified address in the program if there isn't already one there
	 * and if it can be created.
	 * @param program the program
	 * @param functionAddress the entry point address.
	 * @return true if function was created or already exists.
	 */
	public static boolean createFunctionIfNeeded(Program program, Address functionAddress) {
		// If there isn't an instruction at the function address yet, then disassemble there.
		Listing listing = program.getListing();
		functionAddress =
			PseudoDisassembler.getNormalizedDisassemblyAddress(program, functionAddress);
		Instruction inst = listing.getInstructionAt(functionAddress);
		if (inst == null) {
			DisassembleCommand cmd = new DisassembleCommand(functionAddress, null, true);
			if (!cmd.applyTo(program) || cmd.getDisassembledAddressSet().isEmpty()) {
				Msg.error(EHDataTypeUtilities.class, "Failed to disassemble at " + functionAddress);
				return false;
			}
		}

		// If there isn't a function at the function address yet, then try to create one there.
		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunctionAt(functionAddress);
		if (function == null) {
			CreateFunctionCmd cmd = new CreateFunctionCmd(functionAddress);
			if (!cmd.applyTo(program)) {
				Msg.error(EHDataTypeUtilities.class,
					"Failed to create function at " + functionAddress);
				return false;
			}
		}
		return true;
	}

	/**
	 * Determines if the specified address is a valid address in the program's memory.
	 * @param program the program to check.
	 * @param address the address to check.
	 * @return true if the address is valid address in memory.
	 */
	public static boolean isValidAddress(Program program, Address address) {
		if (address == null) {
			throw new IllegalArgumentException("address cannot be null.");
		}
		return program.getMemory().getLoadedAndInitializedAddressSet().contains(address);
	}

	/**
	 * Checks to determine if the address in the indicated program exists in memory and
	 * could possibly be used for creating a function. It is expected to have undefined data
	 * or an instruction at the address.
	 * @param program the program to check.
	 * @param functionAddress the address to check.
	 * @return true if it appears to  be a valid (very loosely defined) location for a function.
	 */
	public static boolean isValidForFunction(Program program, Address functionAddress) {
		if (functionAddress == null) {
			throw new IllegalArgumentException("functionAddress cannot be null.");
		}
		if (!isValidAddress(program, functionAddress)) {
			return false;
		}
		Listing listing = program.getListing();
		// Should be instruction or undefined data.
		return (listing.getInstructionAt(functionAddress) != null) ||
			(listing.getUndefinedDataAt(functionAddress) != null);
	}
}
