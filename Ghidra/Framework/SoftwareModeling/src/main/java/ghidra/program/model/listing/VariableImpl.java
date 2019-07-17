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

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.InvalidInputException;

abstract class VariableImpl implements Variable {

	private String name;
	private DataType dataType;
	private String comment;
	private SourceType sourceType;
	private VariableStorage variableStorage;
	private Program program;

	/**
	 * Construct a variable which has no specific storage specified.  This can be used for
	 * function parameters which will assign storage based upon calling convention
	 * @param name variable name
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param program target program
	 * @param sourceType source type
	 * @throws InvalidInputException if dataType restrictions are violated
	 */
	protected VariableImpl(String name, DataType dataType, Program program, SourceType sourceType)
			throws InvalidInputException {
		this(name, dataType, null, null, null, null, false, program, sourceType);
	}

	/**
	 * Construct a stack variable at the specified stack offset.
	 * @param name variable name or null for default naming
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param stackOffset signed stack offset
	 * @param program target program
	 *  @param sourceType source type
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * address is specified, or unable to resolve storage element for specified datatype
	 * @throws AddressOutOfBoundsException if invalid stack offset specified
	 */
	public VariableImpl(String name, DataType dataType, int stackOffset, Program program,
			SourceType sourceType) throws InvalidInputException {
		this(name, dataType, null, null, stackOffset, null, false, program, sourceType);
	}

	/**
	 * Construct a variable with a single storage element at the specified address.  If address 
	 * is contained within a register it may get realigned to the register based upon the resolved 
	 * datatype length.  Variable storage will be aligned to the least-significant portion of the 
	 * register.
	 * @param name variable name
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param storageAddr storage address or null if no storage has been identified
	 * @param program target program
	 * @param sourceType source type
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * address is specified, or unable to resolve storage element for specified datatype
	 */
	protected VariableImpl(String name, DataType dataType, Address storageAddr, Program program,
			SourceType sourceType) throws InvalidInputException {
		this(name, dataType, null, storageAddr, null, null, false, program, sourceType);
	}

	/**
	 * Construct a variable with a single storage register.  Variable storage will be 
	 * aligned to the least-significant portion of the register.
	 *@param name variable name
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param register register storage
	 * @param program target program
	 * @param sourceType source type
	 * @throws InvalidInputException if dataType restrictions are violated, an invalid storage 
	 * address is specified, or unable to resolve storage element for specified datatype
	 */
	protected VariableImpl(String name, DataType dataType, Register register, Program program,
			SourceType sourceType) throws InvalidInputException {
		this(name, dataType, null, null, null, register, false, program, sourceType);
	}

	/**
	 * Construct a variable with one or more associated storage elements.  Storage elements
	 * may get slightly modified to adjust for the resolved datatype size.
	 * @param name variable name
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param storage variable storage or null for unassigned storage
	 * @param force if true storage will be forced even if incorrect size
	 * @param program target program
	 * @param sourceType source type
	 * @throws InvalidInputException if dataType restrictions are violated or an error occurs while 
	 * resolving storage for specified datatype
	 */
	protected VariableImpl(String name, DataType dataType, VariableStorage storage, boolean force,
			Program program, SourceType sourceType) throws InvalidInputException {
		this(name, dataType, storage, null, null, null, force, program, sourceType);
	}

	/**
	 * Construct a variable.  Only one storage/location may be specified (storage, storageAddr,
	 * stackOffset, register) - all others should be null.  If no storage/location is specified
	 * or is UNASSIGNED, a Void data type may be specified and will be assumed if this type returns
	 * true for {@link #isVoidAllowed()}.
	 * @param name variable name
	 * @param dataType a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
	 * prior to determining storage elements since their length may change)
	 * @param storage variable storage or null for unassigned storage (may be null)
	 * @param storageAddr storage address or null if no storage has been identified (may be null)
	 * @param stackOffset signed stack offset (may be null)
	 * @param register register storage (may be null)
	 * @param force if true storage will be forced even if mismatch with datatype size
	 * @param program target program
	 * @param sourceType source type
	 * @throws InvalidInputException if dataType restrictions are violated or an error occurs while 
	 * resolving storage for specified datatype
	 * @throws AddressOutOfBoundsException if invalid stack offset specified
	 */
	VariableImpl(String name, DataType dataType, VariableStorage storage, Address storageAddr,
			Integer stackOffset, Register register, boolean force, Program program,
			SourceType sourceType) throws InvalidInputException {

		checkUsage(storage, storageAddr, stackOffset, register);
		checkProgram(program);

		this.program = program;
		this.name = name;

		if (storage == null) {
			if (register != null) {
				this.dataType = VariableUtilities.checkDataType(dataType, false,
					register.getMinimumByteSize(), program);
				int size = this.dataType.getLength();
				storageAddr = register.getAddress();
				int regSize = register.getMinimumByteSize();
				if (regSize < size) { // datatype larger than register
					if (!force) {
						throw new InvalidInputException("Register '" + register.getName() +
							"' size too small for specified data type size: " +
							dataType.getLength());
					}
					// allow size mismatch if forced and bypass normal storage computation
					this.variableStorage = new VariableStorage(program, register);
					return;
				}
				else if (register.isBigEndian() && regSize > size) {
					storageAddr = storageAddr.add(regSize - size);
				}
			}
			else {
				if (stackOffset != null) {
					storageAddr =
						program.getAddressFactory().getStackSpace().getAddress(stackOffset);
				}
				this.dataType = VariableUtilities.checkDataType(dataType,
					storageAddr == null && isVoidAllowed(), 1, program);
			}
			this.variableStorage = computeStorage(storageAddr);
		}
		else {
			this.dataType = VariableUtilities.checkDataType(dataType,
				(storage.isVoidStorage() || storage.isUnassignedStorage()) && isVoidAllowed(),
				storage.size(), program);
			VariableUtilities.checkStorage(storage, this.dataType, force);
			this.variableStorage = storage;
		}

		this.sourceType = hasDefaultName() ? SourceType.DEFAULT : sourceType;
	}

	/**
	 * Determine if current name is a default name.  This is more important for parameters
	 * so always returning false for locals is OK.
	 * @return true if name is reserved as a default name
	 */
	protected boolean hasDefaultName() {
		return false;
	}

	private static void checkUsage(VariableStorage storage, Address storageAddr,
			Integer stackOffset, Register register) {
		boolean invalidUsage = false;
		if (storage != null) {
			invalidUsage = storageAddr != null || stackOffset != null || register != null;
		}
		else if (register != null) {
			invalidUsage = storageAddr != null || stackOffset != null;
		}
		else if (stackOffset != null) {
			invalidUsage = storageAddr != null;
		}
		if (invalidUsage) {
			throw new IllegalArgumentException("only one storage location may be specified");
		}
	}

	private static void checkProgram(Program program) {
		if (program == null || program.isClosed()) {
			throw new IllegalArgumentException(
				"An open program object which corresponds to the specified storage is required");
		}
	}

	private VariableStorage computeStorage(Address storageAddr) throws InvalidInputException {
		if (storageAddr == null) {
			return VariableStorage.UNASSIGNED_STORAGE;
		}
		if (!storageAddr.isMemoryAddress() && !storageAddr.isRegisterAddress() &&
			!storageAddr.isStackAddress() && !storageAddr.isHashAddress()) {
			throw new InvalidInputException("Invalid storage address specified: space=" +
				storageAddr.getAddressSpace().getName());
		}
		int dtLength = dataType.getLength();
		if (!storageAddr.isStackAddress()) {
			return new VariableStorage(program, storageAddr, dtLength);
		}

		long stackOffset = storageAddr.getOffset();
		if (stackOffset < 0 && -stackOffset < dtLength) {
			// do not allow stack element to span the 0-offset 
			// i.e., maintain separation of locals and params
			throw new InvalidInputException(
				"Data type does not fit within stack frame constraints (stack offset=" +
					stackOffset + ", size=" + dtLength);
		}
		return new VariableStorage(program, new Varnode(storageAddr, dtLength));
	}

	/**
	 * @return true if a zero-sized void type is permitted
	 */
	protected boolean isVoidAllowed() {
		return false;
	}

	@Override
	public final boolean isValid() {
		DataType dt = getDataType();
		return variableStorage.isValid() &&
			((dt instanceof AbstractFloatDataType) || variableStorage.size() == dt.getLength());
	}

	@Override
	public final String getComment() {
		return comment;
	}

	@Override
	public DataType getDataType() {
		return dataType;
	}

	@Override
	public void setDataType(DataType type, VariableStorage storage, boolean force,
			SourceType source) throws InvalidInputException {
		// stack alignment unknown, force ignored
		// source ignored - normally affects signature source on function only
		type = VariableUtilities.checkDataType(type,
			(storage.isVoidStorage() || storage.isUnassignedStorage()) && isVoidAllowed(),
			storage.size(), program);
		VariableUtilities.checkStorage(storage, type, force);
		dataType = type;
		variableStorage = storage;
	}

	@Override
	public final void setDataType(DataType type, boolean align, boolean force, SourceType source)
			throws InvalidInputException {
		setDataType(type, SourceType.ANALYSIS); // stack alignment unknown, force ignored
	}

	@Override
	public void setDataType(DataType type, SourceType source) throws InvalidInputException {
		type =
			VariableUtilities.checkDataType(type, isVoidAllowed(), dataType.getLength(), program);
		DataType baseType = type;
		if (baseType instanceof TypeDef) {
			baseType = ((TypeDef) baseType).getBaseDataType();
		}
		variableStorage = (baseType instanceof VoidDataType) ? VariableStorage.VOID_STORAGE
				: resizeStorage(variableStorage, type);
		dataType = type;
	}

	@Override
	public Function getFunction() {
		return null;
	}

	@Override
	public final Program getProgram() {
		return program;
	}

	@Override
	public final int getLength() {
		return dataType.getLength();
	}

	@Override
	public final String getName() {
		return name;
	}

	@Override
	public final SourceType getSource() {
		return sourceType != null ? sourceType : SourceType.USER_DEFINED;
	}

	@Override
	public final Symbol getSymbol() {
		return null;
	}

	@Override
	public void setComment(String comment) {
		if (comment != null && comment.endsWith("\n")) {
			comment = comment.substring(0, comment.length() - 1);
		}
		this.comment = comment;
	}

	@Override
	public void setName(String name, SourceType source) throws InvalidInputException {
		this.name = name;
		this.sourceType = hasDefaultName() ? SourceType.DEFAULT : source;
	}

	@Override
	public final boolean hasAssignedStorage() {
		return variableStorage != null;
	}

	@Override
	public final VariableStorage getVariableStorage() {
		return variableStorage;
	}

	@Override
	public final Varnode getFirstStorageVarnode() {
		if (variableStorage != null) {
			return variableStorage.getFirstVarnode();
		}
		return null;
	}

	@Override
	public final Varnode getLastStorageVarnode() {
		if (variableStorage != null) {
			return variableStorage.getLastVarnode();
		}
		return null;
	}

	@Override
	public final boolean isStackVariable() {
		if (variableStorage != null) {
			return variableStorage.isStackStorage();
		}
		return false;
	}

	@Override
	public final boolean hasStackStorage() {
		if (variableStorage != null) {
			return variableStorage.hasStackStorage();
		}
		return false;
	}

	@Override
	public final boolean isRegisterVariable() {
		if (variableStorage != null) {
			return variableStorage.isRegisterStorage();
		}
		return false;
	}

	@Override
	public final Register getRegister() {
		if (variableStorage != null) {
			return variableStorage.getRegister();
		}
		return null;
	}

	@Override
	public final List<Register> getRegisters() {
		if (variableStorage != null) {
			return variableStorage.getRegisters();
		}
		return null;
	}

	@Override
	public final Address getMinAddress() {
		if (variableStorage != null) {
			return variableStorage.getMinAddress();
		}
		return null;
	}

	@Override
	public final int getStackOffset() {
		if (variableStorage != null) {
			return variableStorage.getStackOffset();
		}
		throw new UnsupportedOperationException("Variable is not a stack variable");
	}

	@Override
	public final boolean isMemoryVariable() {
		if (variableStorage != null) {
			return variableStorage.isMemoryStorage();
		}
		return false;
	}

	@Override
	public final boolean isUniqueVariable() {
		if (variableStorage != null) {
			return variableStorage.isHashStorage();
		}
		return false;
	}

	@Override
	public final boolean isCompoundVariable() {
		return variableStorage != null && variableStorage.isCompoundStorage();
	}

	@Override
	public String toString() {
		StringBuilder strBuilder = new StringBuilder();
		strBuilder.append("[");
		strBuilder.append(dataType.getName());
		strBuilder.append(" ");
		strBuilder.append(getName());
		strBuilder.append("@");
		strBuilder.append(variableStorage.toString());
		strBuilder.append("]");
		return strBuilder.toString();
	}

	@Override
	public final boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		if (!(obj instanceof Variable)) {
			return false;
		}

		Variable otherVar = (Variable) obj;

		if (!isEquivalent(otherVar)) {
			return false;
		}
		if (!StringUtils.equals(name, otherVar.getName())) {
			return false;
		}
		return StringUtils.equals(comment, otherVar.getComment());
	}

	@Override
	public int hashCode() {
		int hashcode = getFirstUseOffset();
		hashcode ^= variableStorage.hashCode();
		return hashcode;
	}

	@Override
	public final int compareTo(Variable otherVar) {
		return VariableUtilities.compare(this, otherVar);
	}

	@Override
	public final boolean isEquivalent(Variable otherVar) {
		if (otherVar == null) {
			return false;
		}
		if (otherVar == this) {
			return true;
		}
		if ((otherVar instanceof Parameter) != (this instanceof Parameter)) {
			return false;
		}
		if ((this instanceof Parameter) &&
			((Parameter) this).getOrdinal() != ((Parameter) otherVar).getOrdinal()) {
			return false;
		}
		// Always need to check the storage for a VariableImpl regardless of whether 
		// the otherVar is a VariableDB with custom storage or not.
		if (!SystemUtilities.isEqual(variableStorage, otherVar.getVariableStorage())) {
			return false;
		}
		if (getFirstUseOffset() != otherVar.getFirstUseOffset()) {
			return false;
		}
		if (!DataTypeUtilities.isSameOrEquivalentDataType(getDataType(), otherVar.getDataType())) {
			return false;
		}
		return true;
	}

	///// STORAGE RESIZE /////

	/**
	 * Perform resize variable storage to desired newSize.  This method has limited ability to grow
	 * storage if current storage does not have a stack component or if other space constraints
	 * are exceeded.
	 * @param curStorage
	 * @param newSize
	 * @param type
	 * @param function
	 * @return resize storage
	 * @throws InvalidInputException if unable to resize storage to specified size.
	 */
	private VariableStorage resizeStorage(VariableStorage curStorage, DataType type)
			throws InvalidInputException {
		int newSize = type.getLength();
		int curSize = curStorage.size();
		if (curSize == newSize) {
			return curStorage;
		}
		if (curSize == 0 || curStorage.isUniqueStorage() || curStorage.isHashStorage()) {
			throw new InvalidInputException(
				"Current storage can't be resized: " + curStorage.toString());
		}
		if (newSize > curSize) {
			return expandStorage(curStorage, newSize, type);
		}
		return shrinkStorage(curStorage, newSize, type);
	}

	private VariableStorage shrinkStorage(VariableStorage curStorage, int newSize, DataType type)
			throws InvalidInputException {
		List<Varnode> newList = new ArrayList<>();
		int size = 0;
		for (Varnode vn : curStorage.getVarnodes()) {
			size += vn.getSize();
			if (size >= newSize) {
				newList.add(shrinkVarnode(vn, size - newSize, curStorage, newSize, type));
				break;
			}
			newList.add(vn);
		}
		return new VariableStorage(program, newList);
	}

	private VariableStorage expandStorage(VariableStorage curStorage, int newSize, DataType type)
			throws InvalidInputException {
		List<Varnode> newList = new ArrayList<>();
		Varnode[] varnodes = curStorage.getVarnodes();
		int lastIndex = varnodes.length - 1;
		varnodes[lastIndex] = expandVarnode(varnodes[lastIndex], newSize - curStorage.size(),
			curStorage, newSize, type);
		return new VariableStorage(program, newList);
	}

	private Varnode shrinkVarnode(Varnode varnode, int sizeReduction, VariableStorage curStorage,
			int newSize, DataType type) throws InvalidInputException {
		Address addr = varnode.getAddress();
		if (addr.isStackAddress()) {
			return resizeStackVarnode(varnode, varnode.getSize() - sizeReduction, curStorage,
				newSize, type);
		}
		boolean isRegister = program.getRegister(varnode) != null;
		boolean bigEndian = program.getMemory().isBigEndian();
		boolean complexDt = (type instanceof Composite) || (type instanceof Array);
		if (bigEndian && (isRegister || !complexDt)) {
			return new Varnode(varnode.getAddress().add(sizeReduction),
				varnode.getSize() - sizeReduction);
		}
		return new Varnode(varnode.getAddress(), varnode.getSize() - sizeReduction);
	}

	private Varnode expandVarnode(Varnode varnode, int sizeIncrease, VariableStorage curStorage,
			int newSize, DataType type) throws InvalidInputException {

		Address addr = varnode.getAddress();
		if (addr.isStackAddress()) {
			return resizeStackVarnode(varnode, varnode.getSize() + sizeIncrease, curStorage,
				newSize, type);
		}
		int size = varnode.getSize() + sizeIncrease;
		boolean bigEndian = program.getMemory().isBigEndian();
		Register reg = program.getRegister(varnode);
		Address vnAddr = varnode.getAddress();
		if (reg != null) {
			// Register expansion
			Register newReg = reg;
			while ((newReg.getMinimumByteSize() < size)) {
				newReg = newReg.getParentRegister();
				if (newReg == null) {
					throw new InvalidInputException("Current storage can't be expanded to " +
						newSize + " bytes: " + curStorage.toString());
				}
			}
			if (bigEndian) {
				vnAddr = vnAddr.add(newReg.getMinimumByteSize() - size);
				return new Varnode(vnAddr, size);
			}
		}
		boolean complexDt = (type instanceof Composite) || (type instanceof Array);
		if (bigEndian && !complexDt) {
			return new Varnode(vnAddr.subtract(sizeIncrease), size);
		}
		return new Varnode(vnAddr, size);
	}

	private Varnode resizeStackVarnode(Varnode varnode, int newVarnodeSize,
			VariableStorage curStorage, int newSize, DataType type) throws InvalidInputException {

		Address curAddr = varnode.getAddress();
		int stackOffset = (int) curAddr.getOffset();
		int newStackOffset = stackOffset;

		int newEndStackOffset = newStackOffset + newVarnodeSize - 1;
		if (newStackOffset < 0 && newEndStackOffset >= 0) {
			throw new InvalidInputException(
				"Data type does not fit within variable stack constraints");
		}

		return new Varnode(curAddr.getNewAddress(newStackOffset), newVarnodeSize);
	}

}
