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
package ghidra.app.util;

import java.math.BigInteger;
import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.TypeMismatchException;
import ghidra.util.*;
import ghidra.util.exception.NoValueException;
import ghidra.util.prop.PropertyVisitor;

/**
 * 
 */
abstract class PseudoCodeUnit implements CodeUnit {

	protected Address address;
	protected Address maxAddress;
	protected Program program;
	protected int length;

	protected final static Address[] emptyAddrArray = new Address[0];

	protected int hash;
	protected byte[] bytes;
	protected boolean isBigEndian;

	protected final static Reference[] emptyMemRefs = new Reference[0];

	protected Map<Integer, String> comments = new HashMap<Integer, String>();

	protected ReferenceManager refMgr;

	private boolean isValid = true;

	/**
	 * Creates a pseudo code unit within a program
	 * @param program the program this code unit is in.
	 * @param addr the minimum address of this code unit.
	 * @param length the length  of this code unit.
	 * @param memBuffer the memory buffer where bytes can be obtained for this code unit.
	 * @throws AddressOverflowException if code unit length causes wrap within space
	 */
	PseudoCodeUnit(Program program, Address addr, int length, MemBuffer memBuffer)
			throws AddressOverflowException {
		this(program, addr, length, length, memBuffer);
	}

	/**
	 * Creates a pseudo code unit within a program
	 * @param program the program this code unit is in.
	 * @param addr the minimum address of this code unit.
	 * @param length the length  of this code unit.
	 * @param cacheLength the number of memBuffer bytes to be available within this CodeUnit MemBuffer
	 * @param memBuffer the memory buffer where bytes can be obtained for this code unit.
	 * @throws AddressOverflowException if code unit length causes wrap within space
	 */
	PseudoCodeUnit(Program program, Address addr, int length, int cacheLength, MemBuffer memBuffer)
			throws AddressOverflowException {
		this(addr, length, cacheLength, memBuffer);

		this.program = program;
		if (program != null) {
			refMgr = program.getReferenceManager();
		}
	}

	/**
	 * Creates a pseudo code unit without a program.
	 * @param addr the minimum address of this code unit.
	 * @param length the length  of this code unit.
	 * @param memBuffer the memory buffer where bytes can be obtained for this code unit.
	 * @throws AddressOverflowException if code unit length causes wrap within space
	 */
	PseudoCodeUnit(Address addr, int length, MemBuffer memBuffer)
			throws AddressOverflowException {
		this(addr, length, length, memBuffer);
	}

	/**
	 * Creates a pseudo code unit without a program.
	 * @param addr the minimum address of this code unit.
	 * @param length the length  of this code unit.
	 * @param cacheLength the number of memBuffer bytes to be available within this CodeUnit MemBuffer
	 * @param memBuffer the memory buffer where bytes can be obtained for this code unit.
	 * @throws AddressOverflowException if code unit length causes wrap within space
	 */
	PseudoCodeUnit(Address addr, int length, int cacheLength, MemBuffer memBuffer)
			throws AddressOverflowException {
		this.address = addr;
		this.length = length;
		if (length <= 0) {
			throw new IllegalArgumentException("non-zero positive length required");
		}
		maxAddress = addr.addNoWrap(length - 1);

		isBigEndian = memBuffer.isBigEndian();
		bytes = new byte[cacheLength];
		memBuffer.getBytes(bytes, 0); // unavailable bytes will be 0
		this.hash = address.hashCode();
	}

	private void refresh() {
		// maintain byte cache length which could be longer than length
		bytes = new byte[bytes.length];
		try {
			program.getMemory().getBytes(address, bytes);
			isValid = true;
		}
		catch (MemoryAccessException e) {
			throw new RuntimeException("Not enough bytes in memory buffer to create code unit: " +
				e.getMessage());
		}
	}

	/**
	 * Invalidate memory buffer
	 */
	public void invalidate() {
		if (program == null) {
			throw new UnsupportedOperationException(
				"Pseduo code unit has null program - refresh not supported");
		}
		isValid = false;
	}

	public boolean isValid() {
		return isValid;
	}

	@Override
	public String getAddressString(boolean showBlockName, boolean pad) {
		Address cuAddress = address;
		String addressString = cuAddress.toString(false, pad);
		if (showBlockName && program != null) {
			MemoryBlock block = program.getMemory().getBlock(cuAddress);
			if (block != null) {
				return block.getName() + ":" + addressString;
			}
		}
		return addressString;
	}

	/**
	 * Get the length of the code unit.
	 */
	@Override
	public final int getLength() {
		return length;
	}

	// ///////////////////////////////////////////////////////////////////

	protected void refreshIfNeeded() {
		if (!isValid) {
			refresh();
		}
	}

	/**
	 * Gets the bytes for this code unit.
	 */
	@Override
	public synchronized byte[] getBytes() throws MemoryAccessException {
		refreshIfNeeded();
		if (length == bytes.length) {
			return bytes.clone();
		}
		byte[] byteArray = new byte[length];
		System.arraycopy(bytes, 0, byteArray, 0, length);
		return byteArray;
	}

	@Override
	public int getBytes(byte[] b, int offset) {
		if (program == null) {
			// program not specified - allow partial fill 
			if (offset < 0 || offset >= bytes.length) {
				return 0;
			}
			int len = Math.min(b.length, bytes.length - offset);
			synchronized (this) {
				refreshIfNeeded();
				System.arraycopy(bytes, offset, b, 0, b.length);
			}
			return len;
		}

		// program specified - go for complete fill
		if (offset < 0 || (offset + b.length) > bytes.length) {
			try {
				return program.getMemory().getBytes(address.add(offset), b);
			}
			catch (AddressOutOfBoundsException | MemoryAccessException e) {
				return 0;
			}
		}

		synchronized (this) {
			refreshIfNeeded();
			System.arraycopy(bytes, offset, b, 0, b.length);
			return b.length;
		}
	}

	@Override
	public synchronized void getBytesInCodeUnit(byte[] buffer, int bufferOffset)
			throws MemoryAccessException {
		refreshIfNeeded();
		System.arraycopy(bytes, 0, buffer, bufferOffset, Math.min(buffer.length, length));
	}

	@Override
	public boolean isBigEndian() {
		return isBigEndian;
	}

	@Override
	public short getShort(int offset) throws MemoryAccessException {
		if (isBigEndian) {
			return GhidraBigEndianDataConverter.INSTANCE.getShort(this, offset);
		}
		return GhidraLittleEndianDataConverter.INSTANCE.getShort(this, offset);
	}

	@Override
	public int getInt(int offset) throws MemoryAccessException {
		if (isBigEndian) {
			return GhidraBigEndianDataConverter.INSTANCE.getInt(this, offset);
		}
		return GhidraLittleEndianDataConverter.INSTANCE.getInt(this, offset);
	}

	@Override
	public long getLong(int offset) throws MemoryAccessException {
		if (isBigEndian) {
			return GhidraBigEndianDataConverter.INSTANCE.getLong(this, offset);
		}
		return GhidraLittleEndianDataConverter.INSTANCE.getLong(this, offset);
	}

	@Override
	public BigInteger getBigInteger(int offset, int size, boolean signed)
			throws MemoryAccessException {
		if (isBigEndian) {
			return GhidraBigEndianDataConverter.INSTANCE.getBigInteger(this, offset, size, signed);
		}
		return GhidraLittleEndianDataConverter.INSTANCE.getBigInteger(this, offset, size, signed);
	}

	/**
	 * Set the property name with the given value for this code unit.
	 * @param name the name of the property to save.
	 * @param value the value of the property to save.
	 * 
	 * @throws TypeMismatchException
	 *             if the property manager for name does not support object
	 *             types
	 * @throws ConcurrentModificationException
	 *             if this object is no longer valid.
	 */
	@Override
	public void setProperty(String name, Saveable value) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Set the property name with the given value for this code unit.
	 * @param name the name of the property to save.
	 * @param value the value of the property to save.
	 * 
	 * @throws TypeMismatchException
	 *             if the property manager for name does not support string
	 *             types
	 * @throws ConcurrentModificationException
	 *             if this object is no longer valid.
	 */
	@Override
	public void setProperty(String name, String value) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Set the property name with the given value for this code unit.
	 * @param name the name of the property to save.
	 * @param value the value of the property to save.
	 * 
	 * @throws TypeMismatchException
	 *             if the property manager for name does not support int types
	 * @throws ConcurrentModificationException
	 *             if this object is no longer valid.
	 */
	@Override
	public void setProperty(String name, int value) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Mark the property name as having a value for this code unit.
	 * @param name the name of the property to save.
	 * 
	 * @throws TypeMismatchException
	 *             if the property manager for name does not support void types
	 * @throws ConcurrentModificationException
	 *             if this object is no longer valid.
	 */
	@Override
	public void setProperty(String name) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Get the object property for name; returns null if there is no name
	 * property for this code unit.
	 * @param name the name of the property.
	 * 
	 * @throws TypeMismatchException
	 *             if the property manager for name does not support object
	 *             types
	 * @throws ConcurrentModificationException
	 *             if this object is no longer valid.
	 */
	@Override
	public Saveable getObjectProperty(String name) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Get the string property for name; returns null if there is no name
	 * property for this code unit.
	 * @param name the name of the property.
	 * 
	 * @throws TypeMismatchException
	 *             if the property manager for name does not support string
	 *             types
	 * @throws ConcurrentModificationException
	 *             if this object is no longer valid.
	 */
	@Override
	public String getStringProperty(String name) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Get the int property for name.
	 * @param name the name of the property.
	 * 
	 * @throws NoValueException
	 *             if there is not name property for this code unit
	 * @throws TypeMismatchException
	 *             if the property manager for name does not support int types
	 * @throws ConcurrentModificationException
	 *             if this object is no longer valid.
	 */
	@Override
	public int getIntProperty(String name) throws NoValueException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasProperty(String name) {
		return false;
		//throw new UnsupportedOperationException();
	}

	/**
	 * Returns whether this code unit is marked as having the name property.
	 * @param name the name of the property.
	 * 
	 * @throws TypeMismatchException
	 *             if the property manager for name does not support void types
	 * @throws ConcurrentModificationException
	 *             if this object is no longer valid.
	 */
	@Override
	public boolean getVoidProperty(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<String> propertyNames() {
		throw new UnsupportedOperationException();
	}

	/**
	 * Remove the property value with the given name for this code unit.
	 * @param name the name of the property.
	 */
	@Override
	public void removeProperty(String name) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Invokes the visit() method of the specified PropertyVisitor if the named
	 * property exists for this code unit.
	 * 
	 * @param visitor
	 *            the class implementing the PropertyVisitor interface.
	 * @param propertyName
	 *            the name of the property to be visited.
	 */
	@Override
	public void visitProperty(PropertyVisitor visitor, String propertyName) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Get the label for this code unit.
	 * 
	 * @throws ConcurrentModificationException
	 *             if this object is no longer valid.
	 * @deprecated
	 */
	@Deprecated
	@Override
	public String getLabel() {
		if (program == null)
			return null;
		SymbolTable st = program.getSymbolTable();
		Symbol symbol = st.getPrimarySymbol(address);
		if (symbol == null) {
			return null;
		}
		return symbol.getName();
	}

	/**
	 * Get the symbols for this code unit.
	 * 
	 * @throws ConcurrentModificationException
	 *             if this object is no longer valid.
	 */
	@Override
	public Symbol[] getSymbols() {
		if (program == null)
			return null;
		SymbolTable st = program.getSymbolTable();
		return st.getSymbols(address);
	}

	/**
	 * Get the primary Symbol for this code unit.
	 * 
	 * @throws ConcurrentModificationException
	 *             if this object is no longer valid.
	 */
	@Override
	public Symbol getPrimarySymbol() {
		if (program == null)
			return null;

		SymbolTable st = program.getSymbolTable();
		return st.getPrimarySymbol(address);
	}

	/**
	 * Get the starting address for this code unit.
	 * 
	 * @throws ConcurrentModificationException
	 *             if this object is no longer valid.
	 */
	@Override
	public Address getMinAddress() {
		return address;
	}

	/**
	 * Get the ending address for this code unit.
	 * 
	 * @throws ConcurrentModificationException
	 *             if this object is no longer valid.
	 */
	@Override
	public Address getMaxAddress() {
		return maxAddress;
	}

	/**
	 * Get the code unit after this code unit.
	 * 
	 * @throws ConcurrentModificationException
	 *             if this object is no longer valid.
	 */
	public CodeUnit getNextCodeUnit() {
		if (program == null)
			return null;
		return program.getListing().getCodeUnitAfter(address);
	}

	/**
	 * Get the code unit before this code unit.
	 * 
	 * @throws ConcurrentModificationException
	 *             if this object is no longer valid.
	 */
	public CodeUnit getPreviousCodeUnit() {
		if (program == null)
			return null;
		return program.getListing().getCodeUnitBefore(address);
	}

	/**
	 * Return true if the given CodeUnit follows directly after this code unit.
	 * 
	 * @throws ConcurrentModificationException
	 *             if this object is no longer valid.
	 */
	@Override
	public boolean isSuccessor(CodeUnit codeUnit) {
		Address min = codeUnit.getMinAddress();

		return this.getMaxAddress().isSuccessor(min);
	}

	@Override
	public String getComment(int commentType) {
		return comments.get(commentType);
		//throw new UnsupportedOperationException();
	}

	/**
	 * Get the comment as an array where each element is a single line for the
	 * given type.
	 * 
	 * @param commentType
	 *            must be either EOL_COMMENT_TYPE, PRE_COMMENT_TYPE,
	 *            POST_COMMENT_TYPE, or PLATE_COMMENT_TYPE
	 * @throws IllegalArgumentException
	 *             if type is not one of the three types of comments supported
	 * @throws ConcurrentModificationException
	 *             if this object is no longer valid.
	 */
	@Override
	public String[] getCommentAsArray(int commentType) {
		String comment = comments.get(commentType);
		if (comment == null)
			return new String[0];
		String[] retvals = new String[1];
		retvals[0] = comment;
		return retvals;
		//throw new UnsupportedOperationException();
	}

	/**
	 * Set the comment for the given type.
	 * 
	 * @param commentType
	 *            must be either EOL_COMMENT, PRE_COMMENT, POST_COMMENT, or
	 *            PLATE_COMMENT
	 * @param comment the lines that make up the comment
	 * @throws IllegalArgumentException
	 *             if type is not one of the three types of comments supported
	 * @throws ConcurrentModificationException
	 *             if this object is no longer valid.
	 */
	@Override
	public void setCommentAsArray(int commentType, String comment[]) {
		setComment(commentType, comment[0]);
		//throw new UnsupportedOperationException();
	}

	/**
	 * Set the comment for the given type.
	 * 
	 * @param commentType
	 *            must be either EOL_COMMENT, PRE_COMMENT, POST_COMMENT, or
	 *            PLATE_COMMENT
	 * @param comment the comment
	 * @throws IllegalArgumentException
	 *             if type is not one of the three types of comments supported
	 * @throws ConcurrentModificationException
	 *             if this object is no longer valid.
	 */
	@Override
	public void setComment(int commentType, String comment) {
		comments.put(commentType, comment);
//		String oldValue = comments.get(commentType);
		comments.put(commentType, comment);
//		int changeType;
//		switch (commentType) {
//			case CodeUnit.EOL_COMMENT:
//				changeType = ChangeManager.DOCR_EOL_COMMENT_CHANGED;
//				break;
//			case CodeUnit.PLATE_COMMENT:
//				changeType = ChangeManager.DOCR_PLATE_COMMENT_CHANGED;
//				break;
//			case CodeUnit.POST_COMMENT:
//				changeType = ChangeManager.DOCR_POST_COMMENT_CHANGED;
//				break;
//			case CodeUnit.PRE_COMMENT:
//				changeType = ChangeManager.DOCR_PRE_COMMENT_CHANGED;
//				break;
//			case CodeUnit.REPEATABLE_COMMENT:
//				changeType = ChangeManager.DOCR_REPEATABLE_COMMENT_CHANGED;
//				break;
//			default:
//				changeType = ChangeManager.DOCR_EOL_COMMENT_CHANGED;
//				break;
//		}
//		
//		program.setObjChanged(changeType, getMinAddress(), this, oldValue, comment);
		//throw new UnsupportedOperationException();
	}

	/**
	 * Determines if this code unit contains the indicated address.
	 * @param testAddr the address to test
	 * @return true if address is contained in the range.
	 * @throws ConcurrentModificationException
	 *             if this object is no longer valid.
	 */
	@Override
	public boolean contains(Address testAddr) {
		Address endAddr = address.addWrap(getLength() - 1);
		return address.compareTo(testAddr) <= 0 && testAddr.compareTo(endAddr) <= 0;
	}

	/**
	 * Compares the given address to the address range of this node.
	 * 
	 * @param a the address
	 * @return a negative integer if addr is greater than the maximum range
	 *         address zero if addr is in the range a positive integer if addr
	 *         is less than minimum range address
	 * @throws ConcurrentModificationException
	 *             if this object is no longer valid.
	 */
	@Override
	public int compareTo(Address a) {

		if (contains(a)) {
			return 0;
		}
		return address.compareTo(a);
	}

	/**
	 * Get one byte from memory at the current position plus offset.
	 * 
	 * @param offset
	 *            the displacement from the current position.
	 * @return the data at offset from the current position.
	 * @throws AddressOutOfBoundsException
	 *             if offset exceeds address space
	 * @throws IndexOutOfBoundsException
	 *             if offset is negative
	 * @throws MemoryAccessException
	 *             if memory cannot be read
	 */
	@Override
	public byte getByte(int offset) throws MemoryAccessException {

		// check external to code units owned bytes
		if (offset < 0 || offset >= bytes.length) {
			if (program == null) {
				throw new MemoryAccessException(
					"Pseduo code unit has null program - memory request out of range");
			}
			Memory memory = program.getMemory();
			try {
				return memory.getByte(address.add(offset));
			}
			catch (AddressOutOfBoundsException e) {
				throw new MemoryAccessException(e.getMessage());
			}
		}

		synchronized (this) {
			refreshIfNeeded();
			return bytes[offset];
		}
	}

	/**
	 * Get the Address which corresponds to the offset 0.
	 * 
	 * @return the current address of offset 0.
	 */
	@Override
	public Address getAddress() {
		return address;
	}

	/**
	 * Get the Memory object actually used by the MemBuffer.
	 * 
	 * return the Memory used by this MemBuffer.
	 */
	@Override
	public Memory getMemory() {
		if (program == null)
			return null;
		return program.getMemory();
	}

	/**
	 * Add a reference to the mnemonic for this code unit.
	 * 
	 * @param refAddr
	 *            address of reference to add
	 * @param refType
	 *            type of reference being added
	 */
	@Override
	public void addMnemonicReference(Address refAddr, RefType refType, SourceType sourceType) {
		if (refMgr == null)
			throw new UnsupportedOperationException();
		refMgr.addMemoryReference(address, refAddr, refType, sourceType, MNEMONIC);
	}

	/**
	 * Get references for the mnemonic for this instruction.
	 */
	@Override
	public Reference[] getMnemonicReferences() {
		if (refMgr == null)
			return emptyMemRefs;
		return refMgr.getReferencesFrom(address, MNEMONIC);
	}

	/**
	 * Remove a reference to the mnemonic for this instruction.
	 */
	@Override
	public void removeMnemonicReference(Address refAddr) {
		if (refMgr == null)
			throw new UnsupportedOperationException();
		Reference ref = refMgr.getReference(address, refAddr, MNEMONIC);
		if (ref != null) {
			refMgr.delete(ref);
		}
	}

	/**
	 * Add a user defined reference to the operand at the given index.
	 * @see CodeUnit#addOperandReference(int, Address, RefType, SourceType)
	 */
	@Override
	public void addOperandReference(int opIndex, Address refAddr, RefType type,
			SourceType sourceType) {
		if (refMgr == null)
			throw new UnsupportedOperationException();
		refMgr.addMemoryReference(address, refAddr, type, sourceType, opIndex);
	}

	/**
	 * Get the references for the operand index. If the operand type is a
	 * register, then the user defined references are returned; otherwise an
	 * array with the address for the operand value is returned.
	 */
	@Override
	public Reference[] getOperandReferences(int opIndex) {
		if (refMgr == null)
			return emptyMemRefs;
		return refMgr.getReferencesFrom(address, opIndex);
	}

	/**
	 * Remove a user defined reference to the operand at opIndex.
	 */
	@Override
	public void removeOperandReference(int opIndex, Address refAddr) {
		if (refMgr == null)
			throw new UnsupportedOperationException();
		Reference ref = refMgr.getReference(address, refAddr, opIndex);
		if (ref != null) {
			refMgr.delete(ref);
		}
	}

	/**
	 * Get ALL reference FROM this code unit.
	 */
	@Override
	public Reference[] getReferencesFrom() {
		if (refMgr != null)
			return refMgr.getReferencesFrom(address);
		ArrayList<Reference> list = new ArrayList<Reference>();
		for (int i = 0; i < getNumOperands(); i++) {
			Reference[] refs = getOperandReferences(i);
			for (int j = 0; j < refs.length; j++) {
				list.add(refs[j]);
			}
		}
		return list.toArray(emptyMemRefs);
	}

	public void setExternalReference(Reference ref) {
		throw new UnsupportedOperationException();
	}

	public void setMemoryReference(int opIndex, Address refAddr, RefType refType) {
		throw new UnsupportedOperationException();
	}

	private void validateOpIndex(int opIndex) {
		if (opIndex >= getNumOperands()) {
			throw new IllegalArgumentException("Invalid operand index [" + opIndex + "] specified");
		}
	}

	@Override
	public void setStackReference(int opIndex, int offset, SourceType sourceType, RefType refType) {
		if (refMgr == null)
			throw new UnsupportedOperationException();
		validateOpIndex(opIndex);
		refMgr.addStackReference(address, opIndex, offset, refType, sourceType);
	}

	@Override
	public void setRegisterReference(int opIndex, Register reg, SourceType sourceType,
			RefType refType) {
		if (refMgr == null)
			throw new UnsupportedOperationException();
		validateOpIndex(opIndex);
		refMgr.addRegisterReference(address, opIndex, reg, refType, sourceType);
	}

	@Override
	public Reference getPrimaryReference(int index) {
		if (refMgr == null)
			return null;
		return refMgr.getPrimaryReferenceFrom(address, index);
	}

	@Override
	public void setPrimaryMemoryReference(Reference ref) {
		if (refMgr == null)
			throw new UnsupportedOperationException();
		refMgr.setPrimary(ref, true);
	}

	public StackReference getStackReference(int opIndex) {
		return null;
	}

	public void removeStackReference(int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public ExternalReference getExternalReference(int opIndex) {
		if (refMgr == null)
			return null;
		Reference[] refs = refMgr.getReferencesFrom(address, opIndex);
		for (Reference element : refs) {
			if (element.isExternalReference()) {
				return (ExternalReference) element;
			}
		}
		return null;
	}

	@Override
	public void removeExternalReference(int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public ReferenceIterator getReferenceIteratorTo() {
		if (refMgr == null)
			return null;
		return refMgr.getReferencesTo(address);
	}

	// ///////////////////////////////////////////////////////////////////

	@Override
	public Program getProgram() {
		return program;
	}

	@Override
	public abstract boolean equals(Object obj);

	@Override
	public int hashCode() {
		return address.hashCode();
	}
}
