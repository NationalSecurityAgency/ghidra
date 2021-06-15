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
package ghidra.program.model.data;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.InvalidInputException;

public final class DataUtilities {

	private DataUtilities() {
		// utilities class
	}

	/**
	 * Determine if the specified name is a valid data-type name
	 * @param name candidate data-type name
	 * @return true if name is valid, else false
	 */
	public static boolean isValidDataTypeName(String name) {
		if (name == null || name.length() == 0) {
			return false;
		}

		for (int i = 0; i < name.length(); i++) {
			char c = name.charAt(i);
			// Don't allow control characters, but otherwise accept as much as possible
			//   a) allow spaces and punctuation
			//   b) allow unicode characters (including supplemental characters)
			if (Character.isISOControl(c)) {
				return false;
			}
		}

		return true;
	}

	/**
	 * <code>ClearDataMode</code> specifies how conflicting data should be cleared
	 * when creating/re-creating data
	 */
	public static enum ClearDataMode {
		/**
		 * Ensure that data will fit before clearing
		 * a single code unit at the specified data address.
		 */
		CHECK_FOR_SPACE,
		/**
		 * Always clear a single code unit at the data
		 * address regardless of the ability for the
		 * desired data-type to fit.
		 */
		CLEAR_SINGLE_DATA,
		/**
		 * Clear all conflicting Undefined data provided data will
		 * fit within memory and not conflict with an
		 * instruction or other defined data.  Undefined refers to defined
		 * data with the Undefined data-type.
		 * @see Undefined#isUndefined(DataType)
		 */
		CLEAR_ALL_UNDEFINED_CONFLICT_DATA,
		/**
		 * Clear all conflicting data provided data will
		 * fit within memory and not conflict with an
		 * instruction.
		 */
		CLEAR_ALL_CONFLICT_DATA
	}

	/**
	 * Create data where existing data may already exist.
	 * @param program the program
	 * @param addr data address (offcut data address only allowed if clearMode == ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
	 * @param newType new data-type being applied
	 * @param length data length (used only for Dynamic newDataType which has canSpecifyLength()==true)
	 * @param stackPointers see {@link #reconcileAppliedDataType(DataType, DataType, boolean)}
	 * @param clearMode see CreateDataMode
	 * @return new data created
	 * @throws CodeUnitInsertionException if data creation failed
	 */
	public static Data createData(Program program, Address addr, DataType newType, int length,
			boolean stackPointers, ClearDataMode clearMode) throws CodeUnitInsertionException {

		Listing listing = program.getListing();
		ReferenceManager refMgr = program.getReferenceManager();

		Data data = getData(addr, clearMode, listing);
		int existingLength = addr.getAddressSpace().getAddressableUnitSize();
		DataType existingType = data.getDataType();
		Reference extRef = null;
		if (!isParentData(data, addr)) {

			existingLength = data.getLength();
			if (data.isDefined() && newType.isEquivalent(existingType)) {
				return data;
			}

			if (!stackPointers && clearMode == ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA &&
				!Undefined.isUndefined(existingType)) {
				throw new CodeUnitInsertionException("Could not create Data at address " + addr);
			}

			// TODO: This can probably be eliminated
			// Check for external reference on pointer
			extRef =
				getExternalPointerReference(addr, newType, stackPointers, refMgr, existingType);
		}

		newType = newType.clone(program.getDataTypeManager());
		newType = reconcileAppliedDataType(existingType, newType, stackPointers);

		DataType realType = newType;
		if (newType instanceof TypeDef) {
			realType = ((TypeDef) newType).getBaseDataType();
		}

		// is the datatype already there?
		if (isExistingNonDynamicType(realType, newType, existingType)) {
			return data;
		}

		DataTypeInstance dti = getDtInstance(program, addr, newType, length, realType);
		if (stackPointers && existingType instanceof Pointer && newType instanceof Pointer) {
			listing.clearCodeUnits(addr, addr, false);
		}

		Data newData;
		try {
			newData = listing.createData(addr, dti.getDataType(), dti.getLength());
		}
		catch (CodeUnitInsertionException e) {
			// ok lets see if we need to clear some code units
			if (clearMode == ClearDataMode.CLEAR_SINGLE_DATA) {
				listing.clearCodeUnits(addr, addr, false);
			}
			else {
				checkEnoughSpace(program, addr, existingLength, dti, clearMode);
			}
			newData = listing.createData(addr, dti.getDataType(), dti.getLength());
		}

		restoreReference(newType, refMgr, extRef);

		return newData;
	}

	private static boolean isParentData(Data data, Address addr) {
		return !data.getAddress().equals(addr);
	}

	private static Data getData(Address addr, ClearDataMode clearMode, Listing listing)
			throws CodeUnitInsertionException {

		Data data = listing.getDataAt(addr);
		if (data != null) {
			return data; // existing data; it us possible to create data
		}

		// null data; see if we are in a composite
		if (clearMode == ClearDataMode.CLEAR_ALL_CONFLICT_DATA ||
			clearMode == ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA) {

			// allow offcut addr if CLEAR_ALL_CONFLICT_DATA
			data = listing.getDataContaining(addr);
			if (data != null && clearMode == ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA &&
				!Undefined.isUndefined(data.getDataType())) {
				data = null; // force error
			}
		}

		// null data implies that we cannot create data at this address
		if (data == null) {
			throw new CodeUnitInsertionException("Could not create Data at address " + addr);
		}

		return data;
	}

	private static DataTypeInstance getDtInstance(Program program, Address addr, DataType newType,
			int length, DataType realType) throws CodeUnitInsertionException {

		MemBuffer memBuf = new DumbMemBufferImpl(program.getMemory(), addr);
		DataTypeInstance dti;
		if (length > 0 && (realType instanceof Dynamic) &&
			((Dynamic) realType).canSpecifyLength()) {
			dti = DataTypeInstance.getDataTypeInstance(newType, memBuf, length);
		}
		else {
			dti = DataTypeInstance.getDataTypeInstance(newType, memBuf);
		}

		if (dti == null) {
			throw new CodeUnitInsertionException(
				"Could not create DataType " + newType.getDisplayName());
		}

		return dti;
	}

	private static boolean isExistingNonDynamicType(DataType realType, DataType newType,
			DataType existingType) {

		if (realType instanceof Dynamic || realType instanceof FactoryDataType) {
			return false;
		}

		// not dynamic or factory--does it exist?
		return newType.equals(existingType);
	}

	private static void restoreReference(DataType newType, ReferenceManager refMgr,
			Reference ref) {

		if (ref == null) {
			return;
		}

		if (!(newType instanceof Pointer)) {
			return;
		}

		// if this was a pointer and had an external reference, put it back!
		ExternalLocation extLoc = ((ExternalReference) ref).getExternalLocation();
		Address fromAddress = ref.getFromAddress();
		SourceType source = ref.getSource();
		RefType type = ref.getReferenceType();
		try {
			refMgr.addExternalReference(fromAddress, 0, extLoc, source, type);
		}
		catch (InvalidInputException e) {
			throw new AssertException(e);
		}
	}

	private static Reference getExternalPointerReference(Address addr, DataType newType,
			boolean stackPointers,
			ReferenceManager refMgr, DataType existingType) {
		Reference extRef = null;
		if ((stackPointers || newType instanceof Pointer) &&
			existingType instanceof Pointer) {
			Reference[] refs = refMgr.getReferencesFrom(addr);
			for (Reference ref : refs) {
				if (ref.getOperandIndex() == 0 && ref.isExternalReference()) {
					extRef = ref;
					break;
				}
			}
		}
		return extRef;
	}

	private static void validateCanCreateData(Address addr, ClearDataMode clearMode,
			Listing listing, Data data) throws CodeUnitInsertionException {

		if (data != null) {
			return; // existing data; it us possible to create data
		}

		if (clearMode == ClearDataMode.CLEAR_ALL_CONFLICT_DATA ||
			clearMode == ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA) {

			// allow offcut addr if CLEAR_ALL_CONFLICT_DATA
			data = listing.getDataContaining(addr);
			if (data != null && clearMode == ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA &&
				!Undefined.isUndefined(data.getDataType())) {
				data = null; // force error
			}
		}

		// null data implies that we cannot create data at this address
		if (data == null) {
			throw new CodeUnitInsertionException("Could not create Data at address " + addr);
		}
	}

	private static void checkEnoughSpace(Program program, Address addr, int existingDataLen,
			DataTypeInstance dti, ClearDataMode mode) throws CodeUnitInsertionException {
		// NOTE: method not invoked when clearMode == ClearDataMode.CLEAR_SINGLE_DATA
		Listing listing = program.getListing();
		Address end = null;
		Address newEnd = null;
		try {
			end = addr.addNoWrap(existingDataLen - 1);
			newEnd = addr.addNoWrap(dti.getLength() - 1);
		}
		catch (AddressOverflowException e) {
			throw new CodeUnitInsertionException(
				"Not enough space to create DataType " + dti.getDataType().getDisplayName());
		}

		Instruction instr = listing.getInstructionAfter(end);
		if (instr != null && instr.getMinAddress().compareTo(newEnd) <= 0) {
			throw new CodeUnitInsertionException(
				"Not enough space to create DataType " + dti.getDataType().getDisplayName());
		}

		Data definedData = listing.getDefinedDataAfter(end);
		if (definedData == null || definedData.getMinAddress().compareTo(newEnd) > 0) {
			listing.clearCodeUnits(addr, addr, false);
			return;
		}

		if (mode == ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA &&
			Undefined.isUndefined(definedData.getDataType())) {
			checkForDefinedData(dti, listing, newEnd, definedData.getMaxAddress());
		}
		else if (mode != ClearDataMode.CLEAR_ALL_CONFLICT_DATA) {
			throw new CodeUnitInsertionException("Not enough space to create DataType " +
				dti.getDataType().getDisplayName());
		}
		listing.clearCodeUnits(addr, newEnd, false);
	}

	private static void checkForDefinedData(DataTypeInstance dti, Listing listing, Address address,
			Address end) throws CodeUnitInsertionException {

		// ignore all defined data which is considered Undefined and may be cleared
		while (end.compareTo(address) <= 0) {
			Data definedData = listing.getDefinedDataAfter(end);
			if (definedData == null ||
				definedData.getMinAddress().compareTo(address) > 0) {
				return;
			}

			if (!Undefined.isUndefined(definedData.getDataType())) {
				throw new CodeUnitInsertionException("Not enough space to create DataType " +
					dti.getDataType().getDisplayName());
			}
			end = definedData.getMaxAddress();
		}
	}

	private static DataType stackPointers(Pointer pointer, DataType dataType) {
		DataType dt = pointer.getDataType();
		if (dt instanceof Pointer) {
			return pointer.newPointer(stackPointers((Pointer) dt, dataType));
		}
		return pointer.newPointer(dataType);
	}

	/**
	 * Determine the final data-type which should be applied based upon a
	 * user applied type of newDataType on an existing originalDataType.
	 * Pointer conversion is performed when appropriate, otherwise the
	 * newDataType is returned unchanged.
	 * If newDataType is a FunctionDefinition, or Typedef to a FunctionDefinition, it will either be stacked
	 * with the existing pointer if enabled/applicable, or will be converted to a pointer since
	 * FunctionDefinitions may only been used in the form of a pointer.
	 * Note that originalDataType and newDataType should be actual applied types.
	 * (i.e., do not strip typedefs, pointers, arrays, etc.).
	 * @param originalDataType existing data type onto which newDataTye is applied
	 * @param newDataType new data-type being applied
	 * @param stackPointers If true the following data type transformation will be performed:
	 * <ul>
	 * <li>If newDataType is a default pointer and the originalDataType
	 * is a pointer the new pointer will wrap
	 * the existing pointer thus increasing is 'depth'
	 * (e.g., int * would become int ** when default pointer applied).
	 * If the originalDataType is not a pointer the newDataType will be returned unchanged.
	 * </li>
	 * <li>If the originalDataType is any type of pointer the supplied newDatatype
	 * will replace the pointer's base type (e.g., int * would become db * when
	 * newDataType is {@link ByteDataType}).
	 * </ul>
	 * <P>If false, only required transformations will be applied, Example:
	 * if newDataType is a FunctionDefinitionDataType it will be transformed
	 * to a pointer before being applied.
	 * @return either a combined pointer data-type or the newDataType specified with any
	 * required transformation
	 */
	public static DataType reconcileAppliedDataType(DataType originalDataType, DataType newDataType,
			boolean stackPointers) {
		if (newDataType == DataType.DEFAULT) {
			return newDataType;
		}

		DataType resultDt = newDataType;
		if (stackPointers && isDefaultPointer(newDataType) &&
			(originalDataType instanceof Pointer)) {
			// wrap existing pointer with specified default pointer
			resultDt = ((Pointer) newDataType).newPointer(originalDataType);
		}

		else if (stackPointers && (originalDataType instanceof Pointer)) {
			// replace existing pointer's base data type
			resultDt = stackPointers((Pointer) originalDataType, newDataType);
		}
		else if (newDataType instanceof FunctionDefinition || (newDataType instanceof TypeDef &&
			((TypeDef) newDataType).getBaseDataType() instanceof FunctionDefinition)) {
			resultDt = new PointerDataType(newDataType);
		}
		return resultDt;
	}

	private static boolean isDefaultPointer(DataType dt) {
		if (!(dt instanceof Pointer)) {
			return false;
		}
		Pointer p = (Pointer) dt;
		DataType ptrDt = p.getDataType();
		return ptrDt == null || ptrDt == DataType.DEFAULT;
	}

	/**
	 * Get the data for the given address; if the code unit at the address is
	 * an instruction, return null.
	 * @param loc the location. This provides the address and subcomponent
	 * within the data at the address.
	 * @return the data or null if the code unit at the address is an instruction.
	 */
	public static Data getDataAtLocation(ProgramLocation loc) {
		if (loc == null) {
			return null;
		}

		Address addr = loc.getAddress();
		Listing listing = loc.getProgram().getListing();
		Data dataContaining = listing.getDataContaining(addr);
		if (dataContaining == null) {
			return null;
		}

		Data dataAtAddr = dataContaining.getComponent(loc.getComponentPath());
		return dataAtAddr;
	}

	/**
	 * Get the data for the given address.
	 * <P>
	 * This will return a Data if and only if there is data that starts at the given address.
	 * 
	 * @param program the program 
	 * @param address the data address
	 * @return the Data that starts at the given address or null if the address is code or offcut
	 */
	public static Data getDataAtAddress(Program program, Address address) {
		if (address == null) {
			return null;
		}
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitAt(address);
		if (cu instanceof Data) {
			return (Data) cu;
		}
		return null;
	}

	/**
	 * Get the maximum address of an undefined data range starting at addr.
	 * Both undefined code units and defined data which have an Undefined
	 * data type are included in the range.
	 * @param program the program which will have its code units checked.
	 * @param addr the address where this will start checking for Undefined data. This address can
	 * be offcut into an Undefined Data.
	 * @return end of undefined range or null if addr does not correspond
	 * to an undefined location.
	 */
	public static Address getMaxAddressOfUndefinedRange(Program program, Address addr) {
		Listing listing = program.getListing();
		Data data = listing.getDataContaining(addr);
		if (data == null || !Undefined.isUndefined(data.getDataType())) {
			return null;
		}
		Address endOfRangeAddress = data.getMaxAddress();

		MemoryBlock block = program.getMemory().getBlock(addr);
		if (block == null) {
			return null;
		}
		Address limitAddress = block.getEnd();

		CodeUnit cu = data;
		while (cu != null) {
			if (cu.getAddress().compareTo(limitAddress) > 0) {
				endOfRangeAddress = limitAddress;
				break;
			}
			if (!(cu instanceof Data) || !Undefined.isUndefined(((Data) cu).getDataType())) {
				endOfRangeAddress = cu.getMinAddress().previous();
				break;
			}
			endOfRangeAddress = cu.getMaxAddress();
			cu = listing.getDefinedCodeUnitAfter(endOfRangeAddress);
		}
		if (cu == null) {
			endOfRangeAddress = limitAddress;
		}

		return endOfRangeAddress;
	}

	/**
	 * Determine if the specified addr corresponds to an undefined data location
	 * where both undefined code units and defined data which has an Undefined
	 * data type is considered to be undefined.
	 * @param program the program
	 * @param addr the data address
	 * @return true if the data is undefined
	 */
	public static boolean isUndefinedData(Program program, Address addr) {
		Data data = program.getListing().getDataAt(addr);
		return Undefined.isUndefined(data.getDataType());
	}

	/**
	 * Get the next defined data that comes after the address indicated by addr and that is
	 * no more than the specified maxAddr and that is not a sized undefined data type.
	 * @param program the program whose code units are to be checked to find the next
	 * non-undefined data.
	 * @param addr start looking for data after this address.
	 * @param maxAddr do not look any further than this address.
	 * @return the next defined data that isn't a sized undefined data type, or return null if
	 * there isn't one.
	 */
	public static Data getNextNonUndefinedDataAfter(Program program, Address addr,
			Address maxAddr) {
		// get the next non undefined data element in memory
		Listing listing = program.getListing();
		Address currentAddress = addr;
		Data data = listing.getDefinedDataAfter(currentAddress);
		// Ignore all sized Undefined data types.
		while ((data != null) && (Undefined.isUndefined(data.getDataType())) &&
			currentAddress.compareTo(maxAddr) <= 0) {
			currentAddress = data.getMaxAddress();
			data = listing.getDefinedDataAfter(currentAddress);
		}
		if ((data != null) && (data.getAddress().compareTo(maxAddr) > 0)) {
			return null;
		}
		return data;
	}

	/**
	 * Finds the first conflicting address in the given address range.
	 *
	 * @param program The program.
	 * @param addr The starting address of the range.
	 * @param length The length of the range.
	 * @param ignoreUndefinedData True if the search should ignore {@link Undefined} data as a
	 *   potential conflict, or false if {@link Undefined} data should trigger conflicts.
	 * @return The address of the first conflict in the range, or null if there were no conflicts.
	 */
	public static Address findFirstConflictingAddress(Program program, Address addr, int length,
			boolean ignoreUndefinedData) {
		AddressSet addrSet = new AddressSet(addr, addr.add(length - 1));
		DataIterator definedDataIter = program.getListing().getDefinedData(addrSet, true);
		Data data = null;
		while (definedDataIter.hasNext()) {
			Data d = definedDataIter.next();
			if (!ignoreUndefinedData || !Undefined.isUndefined(d.getDataType())) {
				data = d;
				break;
			}
		}
		InstructionIterator instructionIter = program.getListing().getInstructions(addrSet, true);
		Instruction instruction = instructionIter.hasNext() ? instructionIter.next() : null;
		if (data == null && instruction == null) {
			return null;
		}
		if (data == null) {
			return instruction.getMinAddress();
		}
		if (instruction == null) {
			return data.getMinAddress();
		}
		Address dataAddr = data.getMinAddress();
		Address instructionAddr = instruction.getAddress();
		if (dataAddr.compareTo(instructionAddr) < 0) {
			return dataAddr;
		}
		return instructionAddr;
	}

	/**
	 * Determine if there is only undefined data from the specified startAddress to the specified
	 * endAddress. The start and end addresses must both be in the same defined block of memory.
	 * @param program the program whose code units are to be checked.
	 * @param startAddress start looking for undefined data at this address in a defined memory block.
	 * @param endAddress do not look any further than this address.
	 * This must be greater than or equal to the startAddress and must be in the same memory block
	 * as the start address or false is returned.
	 * @return true if the range of addresses in a memory block is where only undefined data exists.
	 */
	public static boolean isUndefinedRange(Program program, Address startAddress,
			Address endAddress) {
		MemoryBlock block = program.getMemory().getBlock(startAddress);
		// start and end address must be in the same block of memory.
		if (block == null || !block.contains(endAddress)) {
			return false;
		}
		if (startAddress.compareTo(endAddress) > 0) {
			return false; // start shouldn't be after end.
		}
		Listing listing = program.getListing();
		Data data = listing.getDataContaining(startAddress);
		if (data == null || !Undefined.isUndefined(data.getDataType())) {
			return false; // Instruction or Defined Data at startAddress.
		}
		Address maxAddress = data.getMaxAddress();
		while (maxAddress.compareTo(endAddress) < 0) {
			CodeUnit codeUnit = listing.getDefinedCodeUnitAfter(maxAddress);
			if (codeUnit == null) {
				return true; // No more instructions or Defined Data.
			}
			Address minAddress = codeUnit.getMinAddress();
			if (minAddress.compareTo(endAddress) > 0) {
				return true; // Beyond endAddress so all are undefined.
			}
			if (!(codeUnit instanceof Data) ||
				!Undefined.isUndefined(((Data) codeUnit).getDataType())) {
				return false; // Instruction or Defined Data in range.
			}
			maxAddress = codeUnit.getMaxAddress();
		}
		return true; // Got to endAddress with only undefined.
	}
}
