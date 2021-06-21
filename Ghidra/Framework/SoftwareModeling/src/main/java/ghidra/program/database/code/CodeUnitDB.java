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
package ghidra.program.database.code;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import org.apache.commons.lang3.StringUtils;

import db.DBRecord;
import ghidra.program.database.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.*;
import ghidra.program.util.ChangeManager;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.prop.PropertyVisitor;

/**
 * Database implementation of CodeUnit.
 *
 * NOTE!! DataComponents only have a unique key within its parent Struct/Array.  This places a constraint on
 * the use of the key field and getKey() method on the underlying classes CodeUnitDB and DataDB.
 * The CodeUnit key should only be used for managing an object cache.  The addr field should be used within
 * this class instead of the key field.
 */
abstract class CodeUnitDB extends DatabaseObject implements CodeUnit, ProcessorContext {

	protected CodeManager codeMgr;
	protected Address address;
	protected long addr;
	protected Address endAddr;
	protected int length;
	protected ReferenceManager refMgr;
	protected ProgramDB program;

	private DBRecord commentRec;
	private boolean checkedComments;
	protected byte[] bytes;
	private ProgramContext programContext;
	protected ChangeManager changeMgr;
	protected Lock lock;

	/**
	 * Construct a new CodeUnitDB
	 * @param codeMgr code manager that created this codeUnit.
	 * @param cache CodeUnitDB cache
	 * @param cacheKey the cache key (dataComponent does not use the address)
	 * @param address min address of this code unit
	 * @param addr index for min address
	 * @param the length of the codeunit.
	 */
	public CodeUnitDB(CodeManager codeMgr, DBObjectCache<? extends CodeUnitDB> cache, long cacheKey,
			Address address, long addr, int length) {
		super(cache, cacheKey);
		this.codeMgr = codeMgr;
		this.address = address;
		this.addr = addr;
		this.length = length;
		this.lock = codeMgr.lock;
		program = (ProgramDB) codeMgr.getProgram();
		refMgr = program.getReferenceManager();
		programContext = program.getProgramContext();
		changeMgr = program;
	}

	@Override
	protected boolean refresh() {
		return refresh(null);
	}

	@Override
	protected boolean refresh(DBRecord record) {
		address = codeMgr.getAddressMap().decodeAddress(addr);
		endAddr = null;
		commentRec = null;
		checkedComments = false;
		bytes = null;
		return !hasBeenDeleted(record);
	}

	/**
	 * Check this code units validity when the lock/checkIsValid is not used and refresh if necessary.
	 */
	protected void refreshIfNeeded() {
		if (isInvalid()) {
			lock.acquire();
			try {
				refresh();
			}
			finally {
				lock.release();
			}
		}
	}

	/**
	 * Perform any refresh necessary and determine if this code unit has been deleted.
	 * If a record has been provided, it may be used to facilitate a refresh without
	 * performing a record query from the database
	 * @param record optional record which corresponds to code unit.  A null record
	 * does NOT indicate existence and a record query may be required.
	 * @return true if removal of code unit has been confirmed
	 */
	abstract protected boolean hasBeenDeleted(DBRecord record);

	@Override
	public void addMnemonicReference(Address refAddr, RefType refType, SourceType sourceType) {
		refreshIfNeeded();
		refMgr.addMemoryReference(address, refAddr, refType, sourceType, MNEMONIC);
	}

	/**
	 * @see ghidra.program.model.listing.CodeUnit#addOperandReference(int,
	 *      ghidra.program.model.address.Address,
	 *      ghidra.program.model.symbol.RefType, SourceType)
	 */
	@Override
	public void addOperandReference(int opIndex, Address refAddr, RefType type,
			SourceType sourceType) {
		refreshIfNeeded();
		refMgr.addMemoryReference(address, refAddr, type, sourceType, opIndex);
	}

	@Override
	public int compareTo(Address a) {
		refreshIfNeeded();
		if (contains(a)) {
			return 0;
		}
		return address.compareTo(a);
	}

	@Override
	public boolean contains(Address testAddr) {
		refreshIfNeeded();
		return address.compareTo(testAddr) <= 0 && testAddr.compareTo(getMaxAddress()) <= 0;
	}

	@Override
	public String getAddressString(boolean showBlockName, boolean pad) {
		refreshIfNeeded();
		Address cuAddress = address;
		String addressString = cuAddress.toString(false, pad);
		if (showBlockName) {
			MemoryBlock block = program.getMemory().getBlock(cuAddress);
			if (block != null) {
				return block.getName() + ":" + addressString;
			}
		}
		return addressString;
	}

	@Override
	public boolean isBigEndian() {
		return program.getMemory().isBigEndian();
	}

	@Override
	public short getShort(int offset) throws MemoryAccessException {
		if (isBigEndian()) {
			return GhidraBigEndianDataConverter.INSTANCE.getShort(this, offset);
		}
		return GhidraLittleEndianDataConverter.INSTANCE.getShort(this, offset);
	}

	@Override
	public int getInt(int offset) throws MemoryAccessException {
		if (isBigEndian()) {
			return GhidraBigEndianDataConverter.INSTANCE.getInt(this, offset);
		}
		return GhidraLittleEndianDataConverter.INSTANCE.getInt(this, offset);
	}

	@Override
	public long getLong(int offset) throws MemoryAccessException {
		if (isBigEndian()) {
			return GhidraBigEndianDataConverter.INSTANCE.getLong(this, offset);
		}
		return GhidraLittleEndianDataConverter.INSTANCE.getLong(this, offset);
	}

	@Override
	public BigInteger getBigInteger(int offset, int size, boolean signed)
			throws MemoryAccessException {
		if (isBigEndian()) {
			return GhidraBigEndianDataConverter.INSTANCE.getBigInteger(this, offset, size, signed);
		}
		return GhidraLittleEndianDataConverter.INSTANCE.getBigInteger(this, offset, size, signed);
	}

	@Override
	public String getComment(int commentType) {
		lock.acquire();
		try {
			checkIsValid();
			if (!checkedComments) {
				readComments();
			}
			if (commentRec == null) {
				return null;
			}
			return commentRec.getString(commentType);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public String[] getCommentAsArray(int commentType) {
		String comment = getComment(commentType);
		return StringUtilities.toLines(comment);
	}

	@Override
	public ExternalReference getExternalReference(int opIndex) {
		refreshIfNeeded();
		Reference[] refs = refMgr.getReferencesFrom(address, opIndex);
		for (Reference element : refs) {
			if (element.isExternalReference()) {
				return (ExternalReference) element;
			}
		}
		return null;
	}

	@Override
	public int getIntProperty(String name) throws NoValueException {
		PropertyMapManager upm = codeMgr.getPropertyMapManager();
		IntPropertyMap pm = upm.getIntPropertyMap(name);
		if (pm == null) {
			throw NoValueException.noValueException;
		}
		try {
			refreshIfNeeded();
			return pm.getInt(address);
		}
		catch (ConcurrentModificationException e) {
			throw NoValueException.noValueException;
		}
	}

	@Override
	public String getLabel() {
		refreshIfNeeded();
		SymbolTable st = codeMgr.getSymbolTable();
		Symbol symbol = st.getPrimarySymbol(address);
		if (symbol != null) {
			try {
				return symbol.getName();
			}
			catch (ConcurrentModificationException e) {
			}
		}
		return null;
	}

	@Override
	public int getLength() {
		return length;
	}

	@Override
	public Address getMaxAddress() {
		refreshIfNeeded();
		if (endAddr == null) {
			endAddr = address.add(length - 1);
		}
		return endAddr;
	}

	@Override
	public Address getMinAddress() {
		refreshIfNeeded();
		return address;
	}

	@Override
	public Address getAddress() {
		// TODO: Not sure why this method exists?
		refreshIfNeeded();
		return address;
	}

	@Override
	public Reference[] getMnemonicReferences() {
		refreshIfNeeded();
		return refMgr.getReferencesFrom(address, MNEMONIC);
	}

	@Override
	public Saveable getObjectProperty(String name) {
		PropertyMapManager upm = codeMgr.getPropertyMapManager();
		ObjectPropertyMap pm = upm.getObjectPropertyMap(name);
		if (pm != null) {
			try {
				refreshIfNeeded();
				return (Saveable) pm.getObject(address);
			}
			catch (ConcurrentModificationException e) {
			}
		}
		return null;
	}

	@Override
	public Reference[] getOperandReferences(int opIndex) {
		refreshIfNeeded();
		return refMgr.getReferencesFrom(address, opIndex);
	}

	@Override
	public Reference getPrimaryReference(int index) {
		refreshIfNeeded();
		return refMgr.getPrimaryReferenceFrom(address, index);
	}

	@Override
	public Symbol getPrimarySymbol() {
		refreshIfNeeded();
		SymbolTable st = codeMgr.getSymbolTable();
		return st.getPrimarySymbol(address);
	}

	@Override
	public Program getProgram() {
		return program;
	}

	@Override
	public Reference[] getReferencesFrom() {
		refreshIfNeeded();
		return refMgr.getReferencesFrom(address);
	}

	@Override
	public ReferenceIterator getReferenceIteratorTo() {
		refreshIfNeeded();
		return program.getReferenceManager().getReferencesTo(address);
	}

	@Override
	public String getStringProperty(String name) {
		PropertyMapManager upm = codeMgr.getPropertyMapManager();
		StringPropertyMap pm = upm.getStringPropertyMap(name);
		if (pm != null) {
			try {
				refreshIfNeeded();
				return pm.getString(address);
			}
			catch (ConcurrentModificationException e) {
			}
		}
		return null;
	}

	@Override
	public Symbol[] getSymbols() {
		refreshIfNeeded();
		SymbolTable st = codeMgr.getSymbolTable();
		return st.getSymbols(address);
	}

	@Override
	public boolean getVoidProperty(String name) {
		PropertyMapManager upm = codeMgr.getPropertyMapManager();
		PropertyMap pm = upm.getPropertyMap(name);
		if (pm != null) {
			try {
				refreshIfNeeded();
				return pm.hasProperty(address);
			}
			catch (ConcurrentModificationException e) {
			}
		}
		return false;
	}

	@Override
	public boolean hasProperty(String name) {
		PropertyMapManager upm = codeMgr.getPropertyMapManager();
		PropertyMap pm = upm.getPropertyMap(name);
		if (pm != null) {
			try {
				refreshIfNeeded();
				return pm.hasProperty(address);
			}
			catch (ConcurrentModificationException e) {
			}
		}
		return false;
	}

	@Override
	public boolean isSuccessor(CodeUnit codeUnit) {
		Address min = codeUnit.getMinAddress();

		return this.getMaxAddress().isSuccessor(min);
	}

	@Override
	public Iterator<String> propertyNames() {
		PropertyMapManager upm = codeMgr.getPropertyMapManager();
		return upm.propertyManagers();
	}

	@Override
	public void removeExternalReference(int opIndex) {
		Reference ref = getExternalReference(opIndex);
		if (ref != null) {
			program.getReferenceManager().delete(ref);
		}
	}

	@Override
	public void removeMnemonicReference(Address refAddr) {
		refreshIfNeeded();
		Reference ref = refMgr.getReference(address, refAddr, MNEMONIC);
		if (ref != null) {
			program.getReferenceManager().delete(ref);
		}
	}

	@Override
	public void removeOperandReference(int opIndex, Address refAddr) {
		refreshIfNeeded();
		Reference ref = refMgr.getReference(address, refAddr, opIndex);
		if (ref != null) {
			program.getReferenceManager().delete(ref);
		}
	}

	@Override
	public void removeProperty(String name) {
		PropertyMapManager upm = codeMgr.getPropertyMapManager();
		PropertyMap pm = upm.getPropertyMap(name);
		if (pm != null) {
			try {
				refreshIfNeeded();
				pm.remove(address);
			}
			catch (ConcurrentModificationException e) {
			}
		}
	}

	@Override
	public void setComment(int commentType, String comment) {
		lock.acquire();
		try {
			checkDeleted();

			if (!checkedComments) {
				readComments();
			}
			if (commentRec == null) {
				if (comment == null) {
					return;
				}
				try {
					commentRec =
						codeMgr.getCommentAdapter().createRecord(addr, commentType, comment);
				}
				catch (IOException e) {
					codeMgr.dbError(e);
				}
				codeMgr.sendNotification(address, commentType, null, comment);
				return;
			}

			String oldValue = commentRec.getString(commentType);
			commentRec.setString(commentType, comment);
			codeMgr.sendNotification(address, commentType, oldValue, comment);

			for (int i = 0; i < CommentsDBAdapter.COMMENT_COL_COUNT; i++) {
				if (commentRec.getString(i) != null) {
					updateCommentRecord();
					return;
				}
			}
			try {
				codeMgr.getCommentAdapter().deleteRecord(commentRec.getKey());

			}
			catch (IOException e) {
				codeMgr.dbError(e);
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setCommentAsArray(int commentType, String[] comment) {
		setComment(commentType, StringUtils.join(comment, '\n'));
	}

	@Override
	public void setPrimaryMemoryReference(Reference ref) {
		refMgr.setPrimary(ref, true);
	}

	@Override
	public void setProperty(String name, int value) {
		PropertyMapManager upm = codeMgr.getPropertyMapManager();
		lock.acquire();
		try {
			checkDeleted();
			IntPropertyMap pm = upm.getIntPropertyMap(name);

			if (pm == null) {
				try {
					pm = upm.createIntPropertyMap(name);
				}
				catch (DuplicateNameException e) {
					throw new AssertException(
						"Assert problem in CodeUnitImpl.setProperty(String,int)");
				}
			}
			pm.add(address, value);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setProperty(String name, Saveable value) {
		PropertyMapManager mgr = codeMgr.getPropertyMapManager();
		lock.acquire();
		try {
			checkDeleted();
			ObjectPropertyMap pm = mgr.getObjectPropertyMap(name);

			if (pm == null) {
				try {
					pm = mgr.createObjectPropertyMap(name, value.getClass());
				}
				catch (DuplicateNameException e) {
					throw new AssertException(
						"Assert problem in CodeUnitImpl.setProperty(Stirng,Object)");
				}
			}
			pm.add(address, value);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setProperty(String name, String value) {
		PropertyMapManager upm = codeMgr.getPropertyMapManager();
		lock.acquire();
		try {
			checkDeleted();
			StringPropertyMap pm = upm.getStringPropertyMap(name);
			if (pm == null) {
				try {
					pm = upm.createStringPropertyMap(name);
				}
				catch (DuplicateNameException e) {
					throw new AssertException(
						"Assert problem in CodeUnitImpl.setProperty(String,String)");
				}
			}
			pm.add(address, value);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setProperty(String name) {
		PropertyMapManager upm = codeMgr.getPropertyMapManager();
		lock.acquire();
		try {
			checkDeleted();
			VoidPropertyMap pm = upm.getVoidPropertyMap(name);
			if (pm == null) {
				try {
					pm = upm.createVoidPropertyMap(name);
				}
				catch (DuplicateNameException e) {
					throw new AssertException("Assert problem in CodeUnitImpl.setProperty(Stirng)");
				}
			}
			pm.add(address);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setStackReference(int opIndex, int offset, SourceType sourceType, RefType refType) {
		refreshIfNeeded();
		validateOpIndex(opIndex);
		refMgr.addStackReference(address, opIndex, offset, refType, sourceType);
	}

	@Override
	public void setRegisterReference(int opIndex, Register reg, SourceType sourceType,
			RefType refType) {
		refreshIfNeeded();
		validateOpIndex(opIndex);
		refMgr.addRegisterReference(address, opIndex, reg, refType, sourceType);
	}

	@Override
	public void visitProperty(PropertyVisitor visitor, String propertyName) {
		PropertyMapManager upm = codeMgr.getPropertyMapManager();
		PropertyMap pm = upm.getPropertyMap(propertyName);
		if (pm != null) {
			try {
				refreshIfNeeded();
				pm.applyValue(visitor, address);
			}
			catch (ConcurrentModificationException e) {
			}
		}
	}

	@Override
	public int getBytes(byte[] b, int offset) {
		lock.acquire();
		try {
			checkIsValid();
			populateByteArray();
			if (offset < 0 || (offset + b.length) > bytes.length) {
				return program.getMemory().getBytes(address.add(offset), b);
			}
			System.arraycopy(bytes, offset, b, 0, b.length);
			return b.length;
		}
		catch (AddressOutOfBoundsException | MemoryAccessException e) {
			return 0;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public byte[] getBytes() throws MemoryAccessException {
		lock.acquire();
		try {
			checkIsValid();
			populateByteArray();
			byte[] b = new byte[length];
			if (bytes.length < length) {
				if (program.getMemory().getBytes(address, b) != length) {
					throw new MemoryAccessException("Couldn't get all bytes for CodeUnit");
				}
			}
			else {
				System.arraycopy(bytes, 0, b, 0, b.length);
			}
			return b;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public byte getByte(int offset) throws MemoryAccessException {
		lock.acquire();
		try {
			checkIsValid();
			populateByteArray();
			if (offset < 0 || offset >= bytes.length) {
				try {
					return program.getMemory().getByte(address.add(offset));
				}
				catch (AddressOutOfBoundsException e) {
					throw new MemoryAccessException(e.getMessage());
				}
			}
			return bytes[offset];
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Memory getMemory() {
		return program.getMemory();
	}

	@Override
	public BigInteger getValue(Register register, boolean signed) {
		refreshIfNeeded();
		return programContext.getValue(register, address, signed);
	}

	@Override
	public RegisterValue getRegisterValue(Register register) {
		refreshIfNeeded();
		return programContext.getRegisterValue(register, address);
	}

	@Override
	public void setValue(Register register, BigInteger value) throws ContextChangeException {
		refreshIfNeeded();
		programContext.setValue(register, address, address, value);
	}

	@Override
	public void clearRegister(Register register) throws ContextChangeException {
		refreshIfNeeded();
		programContext.setValue(register, address, address, null);
	}

	@Override
	public void setRegisterValue(RegisterValue value) throws ContextChangeException {
		refreshIfNeeded();
		programContext.setRegisterValue(address, address, value);
	}

	@Override
	public Register getRegister(String name) {
		return programContext.getRegister(name);
	}

	@Override
	public Register getBaseContextRegister() {
		return programContext.getBaseContextRegister();
	}

	@Override
	public List<Register> getRegisters() {
		return programContext.getRegisters();
	}

	@Override
	public boolean hasValue(Register register) {
		refreshIfNeeded();
		return programContext.getValue(register, address, false) != null;
	}

	@Override
	public int hashCode() {
		return address.hashCode();
	}

	@Override
	public boolean equals(Object obj) {

		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}

		CodeUnitDB cu = (CodeUnitDB) obj;

		return (addr == cu.addr) && codeMgr == cu.codeMgr;
	}

	/**
	 * Returns a string that represents this code unit with default markup.
	 * Only the mnemonic and operands are included.
	 * @see CodeUnitFormat#getRepresentationString(CodeUnit, boolean) for full mark-up formatting
	 */
	@Override
	public abstract String toString();

	DBRecord getCommentRecord() {
		return commentRec;
	}

	private void readComments() {
		try {
			commentRec = codeMgr.getCommentAdapter().getRecord(addr);
			checkedComments = true;
		}
		catch (IOException e) {
			codeMgr.dbError(e);
		}
	}

	private void populateByteArray() {
		if (bytes != null) {
			return;
		}
		int cacheLength = getPreferredCacheLength();
		bytes = new byte[cacheLength];
		if (cacheLength != 0) {
			int nbytes = 0;
			try {
				nbytes = program.getMemory().getBytes(address, bytes);
			}
			catch (MemoryAccessException e) {
				// ignore
			}
			if (nbytes != bytes.length) {
				bytes = new byte[0];
			}
		}
	}

	protected int getPreferredCacheLength() {
		return length;
	}

	private void validateOpIndex(int opIndex) {
		if (opIndex >= getNumOperands()) {
			throw new IllegalArgumentException("Invalid operand index [" + opIndex + "] specified");
		}
	}

	private void updateCommentRecord() {
		try {
			codeMgr.getCommentAdapter().updateRecord(commentRec);
		}
		catch (IOException e) {
			codeMgr.dbError(e);
		}
	}

	@Override
	public void getBytesInCodeUnit(byte[] buffer, int bufferOffset) throws MemoryAccessException {
		refreshIfNeeded();
		byte[] codeUnitBytes = getBytes();
		System.arraycopy(codeUnitBytes, 0, buffer, bufferOffset,
			Math.min(buffer.length, getLength()));
	}
}
