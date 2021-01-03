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

import generic.algorithms.CRC64;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.UnknownRegister;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.LanguageTranslator;
import ghidra.util.exception.InvalidInputException;

/**
 * <code></code> encapsulates the ordered list of storage varnodes which correspond to a 
 * function parameter or local variable.  For big-endian the first element corresponds 
 * to the most-significant varnode, while for little-endian the first element 
 * corresponds to the least-significant varnode.
 */
public class VariableStorage implements Comparable<VariableStorage> {

	private static final String BAD = "<BAD>";
	private static final String UNASSIGNED = "<UNASSIGNED>";
	private static final String VOID = "<VOID>";

	/**
	 * <code>BAD_STORAGE</code> used to identify variable storage which is no longer
	 * valid.  This can be caused by various events such as significant language/processor
	 * changes or software bugs which prevent variable storage to be properly decoded.
	 */
	public static final VariableStorage BAD_STORAGE = new VariableStorage();

	/**
	 * <code>UNASSIGNED_STORAGE</code> used to identify parameter storage which is "unmapped"
	 * or could not be determined.
	 */
	public static final VariableStorage UNASSIGNED_STORAGE = new VariableStorage();

	/**
	 * <code>VOID_STORAGE</code> used to identify parameter/return storage which is "mapped"
	 * with a data-type of void.
	 */
	public static final VariableStorage VOID_STORAGE = new VariableStorage();

	protected final Varnode[] varnodes;
	protected final Program program;

	private List<Register> registers;
	private int size;
	private long hashcode;
	private String serialization;

	/**
	 * Construct an empty variable storage for reserved usage (i.e., BAD_STORAGE, UNMAPPED_STORAGE)
	 */
	protected VariableStorage() {
		this.program = null;
		this.varnodes = null;
	}

	/**
	 * Construct variable storage
	 * @param program
	 * @param varnodes one or more ordered storage varnodes
	 * @throws InvalidInputException if specified varnodes violate storage restrictions
	 */
	public VariableStorage(Program program, Varnode... varnodes) throws InvalidInputException {
		this.program = program;
		this.varnodes = varnodes.clone();
		checkVarnodes();
	}

	/**
	 * Construct register variable storage
	 * @param program
	 * @param registers one or more ordered registers
	 * @throws InvalidInputException if specified registers violate storage restrictions
	 */
	public VariableStorage(Program program, Register... registers) throws InvalidInputException {
		this(program, getVarnodeList(registers));
	}

	/**
	 * Construct stack variable storage
	 * @param program
	 * @param stackOffset stack offset
	 * @param size stack element size
	 * @throws InvalidInputException if specified registers violate storage restrictions
	 */
	public VariableStorage(Program program, int stackOffset, int size) throws InvalidInputException {
		this(program, new Varnode(program.getAddressFactory().getStackSpace().getAddress(
			stackOffset), size));
	}

	private static Varnode[] getVarnodeList(Register[] registers) {
		Varnode[] varnodes = new Varnode[registers.length];
		for (int i = 0; i < registers.length; i++) {
			varnodes[i] = new Varnode(registers[i].getAddress(), registers[i].getMinimumByteSize());
		}
		return varnodes;
	}

	/**
	 * Construct variable storage
	 * @param program
	 * @param varnodes one or more ordered storage varnodes
	 * @throws InvalidInputException if specified varnodes violate storage restrictions
	 */
	public VariableStorage(Program program, List<Varnode> varnodes) throws InvalidInputException {
		this.program = program;
		this.varnodes = varnodes.toArray(new Varnode[varnodes.size()]);
		checkVarnodes();
	}

	/**
	 * Construct variable storage
	 * @param program
	 * @param address
	 * @param size
	 * @throws InvalidInputException
	 */
	public VariableStorage(Program program, Address address, int size) throws InvalidInputException {
		this(program, new Varnode(address, size));
	}

	/**
	 * Construct variable storage
	 * @param program
	 * @param serialization storage serialization string
	 * @throws InvalidInputException
	 */
	public static VariableStorage deserialize(Program program, String serialization)
			throws InvalidInputException {
		if (serialization == null || UNASSIGNED.equals(serialization)) {
			return UNASSIGNED_STORAGE;
		}
		if (VOID.equals(serialization)) {
			return VOID_STORAGE;
		}
		if (BAD.equals(serialization)) {
			return BAD_STORAGE;
		}
		List<Varnode> varnodes = getVarnodes(program.getAddressFactory(), serialization);
		if (varnodes == null) {
			return BAD_STORAGE;
		}
		return new VariableStorage(program, varnodes);
	}

	/**
	 * @return program for which this storage is associated
	 */
	public Program getProgram() {
		return program;
	}

	/**
	 * @return the total size of corresponding storage varnodes
	 */
	public int size() {
		return size;
	}

	private void checkVarnodes() throws InvalidInputException {
		if (varnodes.length == 0) {
			throw new IllegalArgumentException("A minimum of one varnode must be specified");
		}

		AddressFactory addrFactory = program.getAddressFactory();
		size = 0;
		for (int i = 0; i < varnodes.length; i++) {
			Varnode varnode = varnodes[i];
			if (varnode == null) {
				throw new InvalidInputException("Null varnode not permitted");
			}
			if (varnode.getSize() <= 0) {
				throw new InvalidInputException("Unsupported varnode size: " + varnode.getSize());
			}

			boolean isRegister = false;
			Address storageAddr = varnode.getAddress();
			if (storageAddr.isHashAddress() || storageAddr.isUniqueAddress() ||
				storageAddr.isConstantAddress()) {
				if (varnodes.length != 1) {
					throw new InvalidInputException(
						"Hash, Unique and Constant storage may only use a single varnode");
				}
			}
			else {
				AddressSpace space = addrFactory.getAddressSpace(varnode.getSpace());
				AddressSpace varnodeSpace = varnode.getAddress().getAddressSpace();
				if (space != varnodeSpace) {
					throw new InvalidInputException(
						"Invalid varnode address for specified program: " +
							varnode.getAddress().toString(true));
				}
			}

			if (!storageAddr.isStackAddress()) {
				Register reg = program.getRegister(storageAddr, varnode.getSize());
				if (reg != null && !(reg instanceof UnknownRegister)) {
					isRegister = true;
					if (registers == null) {
						registers = new ArrayList<Register>();
					}
					registers.add(reg);
				}
// The decompiler can create special varnodes in upper bytes of a register
// so we are unable to prevent such varnodes
//				else if (storageAddr.isRegisterAddress()) {
//					throw new InvalidInputException("Variable register not found at " +
//						storageAddr.toString(true) + ", size=" + varnode.getSize() + ")");
//				}
			}
			else {
				long stackOffset = storageAddr.getOffset();
				if (stackOffset < 0 && -stackOffset < varnode.getSize()) {
					// do not allow stack varnode to span the 0-offset 
					// i.e., maintain separation of locals and params
					throw new InvalidInputException(
						"Stack varnode violates stack frame constraints (stack offset=" +
							stackOffset + ", size=" + varnode.getSize());
				}
			}
			if (i < (varnodes.length - 1) && !isRegister) {
				throw new InvalidInputException(
					"Compound storage must use registers except for last varnode");
			}
			size += varnode.getSize();
		}
		for (int i = 0; i < varnodes.length; i++) {
			for (int j = i + 1; j < varnodes.length; j++) {
				if (varnodes[i].intersects(varnodes[j])) {
					throw new InvalidInputException("One or more conflicting varnodes");
				}
			}
		}
	}

	/**
	 * Attempt to clone variable storage for use in a different program.
	 * Dynamic storage characteristics will not be preserved.
	 * @param newProgram target program
	 * @return cloned storage
	 * @throws InvalidInputException 
	 */
	public VariableStorage clone(Program newProgram) throws InvalidInputException {
		if (program == null || newProgram == program) {
			if (getClass().equals(VariableStorage.class)) {
				return this; // only reuse if simple VariableStorage instance
			}
			if (isUnassignedStorage()) {
				return UNASSIGNED_STORAGE;
			}
			if (isBadStorage()) {
				return BAD_STORAGE;
			}
			return new VariableStorage(newProgram, varnodes);
		}
		if (!newProgram.getLanguage().equals(program.getLanguage())) {
			throw new IllegalArgumentException(
				"Variable storage incompatible with program language: " +
					newProgram.getLanguage().toString());
		}
		AddressFactory newAddressFactory = newProgram.getAddressFactory();
		Varnode[] v = getVarnodes();
		Varnode[] newVarnodes = new Varnode[v.length];
		for (int i = 0; i < v.length; i++) {
			AddressSpace newSpace = newAddressFactory.getAddressSpace(v[i].getSpace());
			AddressSpace curSpace = v[i].getAddress().getAddressSpace();
			if (newSpace == null) {
				throw new InvalidInputException(
					"Variable storage incompatible with program, address space not found: " +
						curSpace.getName());
			}
			newVarnodes[i] =
				new Varnode(newSpace.getAddress(v[i].getOffset()), v[i].getSize());
		}
		return new VariableStorage(newProgram, newVarnodes);
	}

	@Override
	public String toString() {
		if (isBadStorage()) {
			return BAD;
		}
		if (isUnassignedStorage()) {
			return UNASSIGNED;
		}
		if (isVoidStorage()) {
			return VOID;
		}
		StringBuilder builder = new StringBuilder();
		Varnode varnode = varnodes[0];
		addVarnodeInfo(builder, varnode);
		for (int i = 1; i < varnodes.length; i++) {
			builder.append(",");
			addVarnodeInfo(builder, varnodes[i]);
		}
		return builder.toString();
	}

	private void addVarnodeInfo(StringBuilder builder, Varnode varnode) {
		Address address = varnode.getAddress();
		builder.append(getAddressString(address, varnode.getSize()));
		builder.append(":");
		builder.append(varnode.getSize());
	}

	private String getAddressString(Address address, int size) {
		if (address.isRegisterAddress() || address.isMemoryAddress()) {
			Register register = program.getRegister(address, size);
			if (register != null) {
				return register.toString();
			}
		}
		return address.toString();
	}

	/**
	 * @return the number of varnodes associated with this variable storage
	 */
	public int getVarnodeCount() {
		if (varnodes == null) {
			return 0;
		}
		return varnodes.length;
	}

	/**
	 * @return ordered varnodes associated with this variable storage
	 */
	public Varnode[] getVarnodes() {
		if (varnodes == null) {
			return new Varnode[0];
		}
		return varnodes.clone();
	}

	/**
	 * Associated with auto-parameters.  Parameters whose existence is dictated
	 * by a calling-convention may automatically inject additional hidden
	 * parameters.  If this storage is associated with a auto-parameter, this
	 * method will return true.   
	 * @return true if this storage is associated with an auto-parameter, else false
	 */
	public boolean isAutoStorage() {
		return false;
	}

	/**
	 * If this storage corresponds to a auto-parameter, return the type associated
	 * with the auto-parameter.
	 * @return auto-parameter type or null if not applicable
	 */
	public AutoParameterType getAutoParameterType() {
		return null;
	}

	/**
	 * If this storage corresponds to parameter which was forced by the associated calling 
	 * convention to be passed as a pointer instead of its raw type.
	 * @return true if this parameter was forced to be passed as a pointer instead of its raw type
	 */
	public boolean isForcedIndirect() {
		return false;
	}

	/**
	 * @return true if this storage is bad (could not be resolved)
	 */
	public boolean isBadStorage() {
		return this == BAD_STORAGE;
	}

	/**
	 * @return true if storage has not been assigned (no varnodes)
	 */
	public boolean isUnassignedStorage() {
		return this == UNASSIGNED_STORAGE;
	}

	/**
	 * @return true if storage is assigned and is not BAD
	 */
	public boolean isValid() {
		return !isUnassignedStorage() && !isBadStorage();
	}

	/**
	 * @return true if storage corresponds to the VOID_STORAGE instance
	 * @see #VOID_STORAGE
	 */
	public boolean isVoidStorage() {
		return this == VOID_STORAGE;
	}

	/**
	 * @return first varnode within the ordered list of varnodes
	 */
	public Varnode getFirstVarnode() {
		return (varnodes == null || varnodes.length == 0) ? null : varnodes[0];
	}

	/**
	 * @return last varnode within the ordered list of varnodes
	 */
	public Varnode getLastVarnode() {
		return (varnodes == null || varnodes.length == 0) ? null : varnodes[varnodes.length - 1];
	}

	/**
	 * @return true if storage consists of a single stack varnode
	 */
	public boolean isStackStorage() {
		if (varnodes == null || varnodes.length == 0) {
			return false;
		}
		// check first varnode for stack use
		Address storageAddr = getFirstVarnode().getAddress();
		return storageAddr.isStackAddress();
	}

	/**
	 * @return true if the last varnode for simple or compound storage is a stack varnode
	 */
	public boolean hasStackStorage() {
		if (varnodes == null || varnodes.length == 0) {
			return false;
		}
		// check last varnode for stack use
		Address storageAddr = getLastVarnode().getAddress();
		return storageAddr.isStackAddress();
	}

	/**
	 * @return true if this is a simple variable consisting of a single register varnode
	 * which will be returned by either the {@link Variable#getFirstStorageVarnode()} or 
	 * {@link Variable#getLastStorageVarnode()} methods.  The register can be obtained using the 
	 * {@link #getRegister()} method.  Keep in mind that registers
	 * may exist in a memory space or the register space.
	 */
	public boolean isRegisterStorage() {
		return varnodes != null && varnodes.length == 1 && registers != null;
	}

	/**
	 * @return first storage register associated with this register or compound storage, else
	 * null is returned.
	 * @see Variable#isRegisterVariable()
	 */
	public Register getRegister() {
		return registers != null ? registers.get(0) : null;
	}

	/**
	 * @return storage register(s) associated with this register or compound storage, else
	 * null is returned.
	 * @see Variable#isRegisterVariable()
	 * @see #isCompoundStorage()
	 */
	public List<Register> getRegisters() {
		return registers;
	}

	/**
	 * @return the stack offset associated with simple stack storage or compound 
	 * storage where the last varnode is stack, see {@link #hasStackStorage()}. 
	 * @throws UnsupportedOperationException if storage does not have a stack varnode
	 */
	public int getStackOffset() {
		if (varnodes != null && varnodes.length != 0) {
			Address storageAddr = getLastVarnode().getAddress();
			if (storageAddr.isStackAddress()) {
				return (int) storageAddr.getOffset();
			}
		}
		throw new UnsupportedOperationException("Storage does not have a stack varnode");
	}

	/**
	 * @return the minimum address corresponding to the first varnode of this storage
	 * or null if this is a special empty storage: {@link #isBadStorage()}, {@link #isUnassignedStorage()},
	 * {@link #isVoidStorage()}
	 */
	public Address getMinAddress() {
		if (varnodes == null || varnodes.length == 0) {
			return null;
		}
		return varnodes[0].getAddress();
	}

	/**
	 * @return true if storage consists of a single memory varnode which does not correspond
	 * to a register.
	 */
	public boolean isMemoryStorage() {
		if (varnodes == null || varnodes.length == 0) {
			return false;
		}
		Address storageAddr = varnodes[0].getAddress();
		return storageAddr.isMemoryAddress() && (registers == null);
	}

	/**
	 * @return true if storage consists of a single constant-space varnode which is used when storing
	 * local function constants.
	 */
	public boolean isConstantStorage() {
		if (varnodes == null || varnodes.length == 0) {
			return false;
		}
		Address storageAddr = varnodes[0].getAddress();
		return storageAddr.isConstantAddress();
	}

	/**
	 * @return true if storage consists of a single hash-space varnode which is used when storing
	 * local unique function variables.
	 */
	public boolean isHashStorage() {
		if (varnodes == null || varnodes.length == 0) {
			return false;
		}
		Address storageAddr = varnodes[0].getAddress();
		return storageAddr.isHashAddress();
	}

	/**
	 * @return true if storage consists of a single unique-space varnode which is used during
	 * function analysis.  This type of storage is not suitable for database-stored function
	 * variables.  This type of storage must be properly converted to Hash storage when 
	 * storing unique function variables.
	 */
	public boolean isUniqueStorage() {
		if (varnodes == null || varnodes.length == 0) {
			return false;
		}
		Address storageAddr = varnodes[0].getAddress();
		return storageAddr.isUniqueAddress();
	}

	/**
	 * @return true if storage consists of two or more storage varnodes
	 */
	public boolean isCompoundStorage() {
		return varnodes != null && varnodes.length > 1;
	}

	public long getLongHash() {
		if (hashcode == 0) {
			// WARNING! This can not be changed since this hash is used to 
			// locate existing storage records which have previously 
			// stored this hash
			CRC64 crc = new CRC64();
			byte[] bytes = getSerializationString().getBytes();
			crc.update(bytes, 0, bytes.length);
			hashcode = crc.finish();
		}
		return hashcode;
	}

	@Override
	public int hashCode() {
		return (int) getLongHash();
		//return (varnodes == null || varnodes.length == 0) ? 0 : varnodes[0].hashCode();
	}

	/**
	 * This storage is considered equal if it consists of the same storage varnodes.
	 */
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof VariableStorage)) {
			return false;
		}
		VariableStorage otherVS = (VariableStorage) obj;
		if (isAutoStorage() != otherVS.isAutoStorage()) {
			return false;
		}
		if (isForcedIndirect() != otherVS.isForcedIndirect()) {
			return false;
		}
		if (isBadStorage() != otherVS.isBadStorage()) {
			return false;
		}
		if (isUnassignedStorage() != otherVS.isUnassignedStorage()) {
			return false;
		}
		if (isVoidStorage() != otherVS.isVoidStorage()) {
			return false;
		}
		return compareTo(otherVS) == 0;
	}

	/**
	 * Determine if this variable storage intersects the specified variable storage
	 * @param variableStorage
	 * @return true if any intersection exists between this storage and the specified
	 * variable storage
	 */
	public boolean intersects(VariableStorage variableStorage) {
		Varnode[] otherVarnodes = variableStorage.varnodes;
		if (varnodes == null || otherVarnodes == null) {
			return false;
		}
		for (int i = 0; i < varnodes.length; i++) {
			for (int j = 0; j < otherVarnodes.length; j++) {
				if (varnodes[i].intersects(otherVarnodes[j])) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Determine if this storage intersects the specified address set
	 * @param set address set
	 * @return true if this storage intersects the specified address set
	 */
	public boolean intersects(AddressSetView set) {
		if (varnodes == null || set == null || set.isEmpty()) {
			return false;
		}
		for (int i = 0; i < varnodes.length; i++) {
			if (varnodes[i].intersects(set)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Determine if this storage intersects the specified register
	 * @param reg the register
	 * @return true if this storage intersects the specified register
	 */
	public boolean intersects(Register reg) {
		if (varnodes == null || reg == null) {
			return false;
		}
		Varnode regVarnode = new Varnode(reg.getAddress(), reg.getMinimumByteSize());
		for (int i = 0; i < varnodes.length; i++) {
			if (varnodes[i].intersects(regVarnode)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Determine if the specified address is contained within this storage
	 * @param address
	 * @return
	 */
	public boolean contains(Address address) {
		if (varnodes == null) {
			return false;
		}
		for (int i = 0; i < varnodes.length; i++) {
			if (varnodes[i].contains(address)) {
				return true;
			}
		}
		return false;
	}

	private static final int PRECEDENCE_MAPPED = 1;
	private static final int PRECEDENCE_UNMAPPED = 2;
	private static final int PRECEDENCE_BAD = 3;

	private static int getPrecedence(VariableStorage storage) {
		if (storage.isUnassignedStorage()) {
			return PRECEDENCE_UNMAPPED;
		}
		if (storage.varnodes != null && storage.varnodes.length != 0) {
			return PRECEDENCE_MAPPED;
		}
		return PRECEDENCE_BAD;
	}

	/**
	 * Compare this variable storage with another.  A value of 0 indicates 
	 * that the two objects are equal
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(VariableStorage otherStorage) {
		int myPrecedence = getPrecedence(this);
		int otherPrecedence = getPrecedence(otherStorage);
		int diff = myPrecedence - otherPrecedence;
		if (diff != 0 || myPrecedence != PRECEDENCE_MAPPED) {
			return diff;
		}
		int compareIndexCnt = Math.min(varnodes.length, otherStorage.varnodes.length);
		for (int i = 0; i < compareIndexCnt; i++) {
			Address myStorageAddr = varnodes[i].getAddress();
			Address otherStorageAddr = otherStorage.varnodes[i].getAddress();
			diff = myStorageAddr.compareTo(otherStorageAddr);
			if (diff != 0) {
				return diff;
			}
			diff = varnodes[i].getSize() - otherStorage.varnodes[i].getSize();
			if (diff != 0) {
				return diff;
			}
		}
		return varnodes.length - otherStorage.varnodes.length;
	}

	/**
	 * Return a serialization form of this variable storage.
	 * @return storage serialization string useful for subsequent reconstruction
	 */
	public String getSerializationString() {

		if (serialization != null) {
			return serialization;
		}

		if (isBadStorage()) {
			serialization = BAD;
		}
		else if (isUnassignedStorage()) {
			serialization = UNASSIGNED;
		}
		else if (isVoidStorage()) {
			serialization = VOID;
		}
		else {
			serialization = getSerializationString(varnodes);
		}
		return serialization;
	}

	/**
	 * Generate VariableStorage serialization string
	 * @param varnodes
	 * @return storage serialization string useful for subsequent reconstruction
	 * of a VariableStorage object
	 */
	public static String getSerializationString(Varnode... varnodes) {
		if (varnodes == null || varnodes.length == 0) {
			throw new IllegalArgumentException("varnodes may not be null or empty");
		}
		StringBuilder strBuilder = new StringBuilder();
		for (Varnode v : varnodes) {
			if (strBuilder.length() != 0) {
				strBuilder.append(",");
			}
			strBuilder.append(v.getAddress().toString(true));
			strBuilder.append(":");
			strBuilder.append(Integer.toString(v.getSize()));
		}
		return strBuilder.toString();
	}

	/**
	 * Parse a storage serialization string to produce an array or varnodes
	 * @param addrFactory
	 * @param serialization
	 * @return array of varnodes or null if invalid
	 */
	public static List<Varnode> getVarnodes(AddressFactory addrFactory, String serialization)
			throws InvalidInputException {
		if (BAD.equals(serialization)) {
			return null;
		}
		ArrayList<Varnode> list = new ArrayList<Varnode>();
		String[] varnodeStrings = serialization.split(",");
		try {
			for (String piece : varnodeStrings) {
				int index = piece.lastIndexOf(':');
				if (index <= 0) {
					list = null;
					break;
				}
				String addrStr = piece.substring(0, index);
				String sizeStr = piece.substring(index + 1);
				Address addr = addrFactory.getAddress(addrStr);
				if (addr == null) {
					list = null;
					break;
				}
				if (addr == Address.NO_ADDRESS) {
					return null;
				}
				int size = Integer.parseInt(sizeStr);
				list.add(new Varnode(addr, size));
			}
		}
		catch (NumberFormatException e) {
			list = null;
		}
		if (list == null) {
			throw new InvalidInputException("Invalid varnode serialization: '" + serialization +
				"'");
		}
		return list;
	}

	/**
	 * Perform language translations on VariableStorage serialization string
	 * @param translator language translator
	 * @param serialization VariableStorage serialization string
	 * @return translated serialization string
	 * @throws InvalidInputException if serialization has invalid format
	 */
	public static String translateSerialization(LanguageTranslator translator, String serialization)
			throws InvalidInputException {
		if (serialization == null || UNASSIGNED.equals(serialization)) {
			return null;
		}
		if (VOID.equals(serialization)) {
			return VOID;
		}
		if (BAD.equals(serialization)) {
			return BAD;
		}

		StringBuilder strBuilder = new StringBuilder();
		String[] varnodeStrings = serialization.split(",");
		for (String piece : varnodeStrings) {
			int index = piece.lastIndexOf(':');
			if (index <= 0) {
				strBuilder = null;
				break;
			}

			if (strBuilder.length() != 0) {
				strBuilder.append(",");
			}

			String addrStr = piece.substring(0, index);
			String sizeStr = piece.substring(index + 1);

			index = addrStr.indexOf(':');
			if (index > 0) {
				String spaceName = addrStr.substring(0, index);
				String offsetStr = addrStr.substring(index + 1);
				AddressSpace space = translator.getNewAddressSpace(spaceName);
				if (space != null) {

					// Handle register movement within register space only
					// Assumes all translators will map register space properly
					if (space.isRegisterSpace()) {
						long offset = Long.parseUnsignedLong(offsetStr, 16);
						int size = Integer.parseInt(sizeStr);
						Address oldRegAddr =
							translator.getOldLanguage().getAddressFactory().getRegisterSpace().getAddress(
								offset);
						String newOffsetStr =
							translateRegisterVarnodeOffset(oldRegAddr, size, translator, space);
						if (newOffsetStr != null) {
							// if mapping failed - leave it unchanged
							offsetStr = newOffsetStr;
						}
					}
					strBuilder.append(space.getName());
					strBuilder.append(':');
					strBuilder.append(offsetStr);
					strBuilder.append(':');
					strBuilder.append(sizeStr);
					continue;
				}
				// else don't translate varnode - assume overlay and leave it alone
			}
			// else don't translate varnode - assume Stack or other special encoding

			// no translation needed
			strBuilder.append(piece);
		}

		if (strBuilder == null) {
			throw new InvalidInputException("Invalid varnode serialization: '" + serialization +
				"'");
		}

		return strBuilder.toString();
	}

	/**
	 * Translate register varnode address offsetStr
	 * @param translator
	 * @param space
	 * @param offsetStr
	 * @param sizeStr
	 * @return translated offsetStr or null if BAD translation
	 */
	private static String translateRegisterVarnodeOffset(Address oldRegAddr, int varnodeSize,
			LanguageTranslator translator, AddressSpace newRegisterSpace) {
		// Handle register movement within register space only
		// Assumes all translators will map register space properly
		// If old or new register not found no adjustment is made
		// The original addrStr may refer to an offcut location within a register 
		long offset = oldRegAddr.getOffset();
		Register oldReg = translator.getOldRegister(oldRegAddr, varnodeSize);
		if (oldReg == null) {
			// possible offcut register varnode
			oldReg = translator.getOldRegisterContaining(oldRegAddr);
		}
		if (oldReg != null && !(oldReg instanceof UnknownRegister)) {
			Register newReg = translator.getNewRegister(oldReg);
			if (newReg != null) { // assume reg endianess unchanged
				// NOTE: could produce bad results if not careful with mapping
				int origByteShift = (int) offset - oldReg.getOffset();
				offset = newReg.getOffset() + origByteShift;
				if (newReg.isBigEndian()) {
					// maintain right alignment for BE
					int regSizeDiff = newReg.getMinimumByteSize() - oldReg.getMinimumByteSize();
					offset += regSizeDiff;
					if (offset < newReg.getOffset()) {
						return null; // BE - did not fit
					}
				}
				else if ((origByteShift + varnodeSize) > newReg.getMinimumByteSize()) {
					return null; // LE - did not fit
				}
				return Long.toHexString(offset);
			}
		}
		return null; // translation failed
	}

}
