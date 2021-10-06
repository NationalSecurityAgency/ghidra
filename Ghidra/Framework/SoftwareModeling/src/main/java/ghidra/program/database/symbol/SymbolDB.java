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
package ghidra.program.database.symbol;

import java.io.IOException;
import java.util.*;

import db.DBRecord;
import db.Field;
import ghidra.program.database.*;
import ghidra.program.database.external.ExternalLocationDB;
import ghidra.program.database.external.ExternalManagerDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ChangeManager;
import ghidra.util.Lock;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.UnknownProgressWrappingTaskMonitor;

/**
 * Base class for symbols
 */
public abstract class SymbolDB extends DatabaseObject implements Symbol {

	private DBRecord record;
	private boolean isDeleting = false;
	protected Address address;
	protected SymbolManager symbolMgr;
	protected Lock lock;

	private volatile String cachedName;
	private volatile long cachedNameModCount;

	SymbolDB(SymbolManager symbolMgr, DBObjectCache<SymbolDB> cache, Address address,
			DBRecord record) {
		super(cache, record.getKey());
		this.symbolMgr = symbolMgr;
		this.address = address;
		this.record = record;
		lock = symbolMgr.getLock();
	}

	SymbolDB(SymbolManager symbolMgr, DBObjectCache<SymbolDB> cache, Address address, long key) {
		super(cache, key);
		this.symbolMgr = symbolMgr;
		this.address = address;
		lock = symbolMgr.getLock();
	}

	@Override
	public boolean isDeleted() {
		return isDeleted(lock);
	}

	@Override
	protected void checkDeleted() {
		// expose method to symbol package
		super.checkDeleted();
	}

	@Override
	public String toString() {
		return getName();
	}

	@Override
	protected boolean refresh() {
		return refresh(null);
	}

	@Override
	protected boolean refresh(DBRecord rec) {
		if (record != null) {
			if (rec == null) {
				rec = symbolMgr.getSymbolRecord(key);
			}
			if (rec == null ||
				record.getByteValue(SymbolDatabaseAdapter.SYMBOL_TYPE_COL) != rec.getByteValue(
					SymbolDatabaseAdapter.SYMBOL_TYPE_COL)) {
				return false;
			}
			record = rec;
			address = symbolMgr.getAddressMap()
					.decodeAddress(
						rec.getLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL));
			return true;
		}
		return false;
	}

	@Override
	public Address getAddress() {
		lock.acquire();
		try {
			checkIsValid();
			return address;
		}
		finally {
			lock.release();
		}
	}

	protected void setAddress(Address addr) {
		if (!(this instanceof VariableSymbolDB)) {
			throw new IllegalArgumentException("Address setable for variables only");
		}
		ProgramDB program = symbolMgr.getProgram();
		record.setLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL,
			program.getAddressMap().getKey(addr, true));
		updateRecord();
		Address oldAddr = address;
		address = addr;
		program.symbolChanged(this, ChangeManager.DOCR_SYMBOL_ADDRESS_CHANGED, oldAddr, this,
			oldAddr, addr);
	}

	/**
	 * 	low level record adjustment to move a symbol. Used only when moving a memory block or
	 *  changing the image base.
	 *  
	 * @param newAddress the new address for the symbol
	 * @param newName the new name for the symbol (or null if the name should stay the same)
	 * @param newNamespace the new namespace for the symbol (or null if it should stay the same)
	 * @param newSource the new SourceType for the symbol (or null if it should stay the same)
	 * @param pinned the new pinned state
	 */
	protected void moveLowLevel(Address newAddress, String newName, Namespace newNamespace,
			SourceType newSource, boolean pinned) {
		lock.acquire();
		try {
			checkDeleted();

			// update the address to the new location
			long newAddressKey = symbolMgr.getAddressMap().getKey(newAddress, true);
			record.setLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL, newAddressKey);

			// if the primary field is set, be sure to update it to the new address as well
			if (record.getFieldValue(SymbolDatabaseAdapter.SYMBOL_PRIMARY_COL) != null) {
				record.setLongValue(SymbolDatabaseAdapter.SYMBOL_PRIMARY_COL, newAddressKey);
			}
			if (newName != null) {
				record.setString(SymbolDatabaseAdapter.SYMBOL_NAME_COL, newName);
			}
			if (newNamespace != null) {
				record.setLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_COL, newNamespace.getID());
			}
			if (newSource != null) {
				setSourceFlagBit(newSource);
			}
			updatePinnedFlag(pinned);
			updateRecord();
			setInvalid();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public final String getName() {
		String name = cachedName;
		if (hasValidCachedName(name)) {
			return name;
		}

		lock.acquire();
		try {
			checkIsValid();
			cachedName = doGetName();
			cachedNameModCount = symbolMgr.getProgram().getModificationNumber();
			return cachedName;
		}
		finally {
			lock.release();
		}
	}

	private boolean hasValidCachedName(String name) {
		if (name == null) {
			return false;
		}
		return symbolMgr.getProgram().getModificationNumber() == cachedNameModCount;
	}

	/**
	 * The code for creating the name content for this symbol.  This code will be called 
	 * with the symbol's lock.
	 * 
	 * @return the name
	 */
	protected String doGetName() {
		if (record != null) {
			return record.getString(SymbolDatabaseAdapter.SYMBOL_NAME_COL);
		}
		return SymbolUtilities.getDynamicName(symbolMgr.getProgram(), address);
	}

	@Override
	public Program getProgram() {
		return symbolMgr.getProgram();
	}

	@Override
	public String getName(boolean includeNamespace) {
		lock.acquire();
		try {
			checkIsValid();
			String symName = getName();
			if (includeNamespace) {
				Namespace ns = getParentNamespace();
				if (!(ns instanceof GlobalNamespace)) {
					String nsPath = ns.getName(true);
					symName = nsPath + Namespace.DELIMITER + symName;
				}
			}
			return symName;
		}
		finally {
			lock.release();
		}
	}

	private void fillListWithNamespacePath(Namespace namespace, ArrayList<String> list) {
		Namespace parentNamespace = namespace.getParentNamespace();
		if (parentNamespace != null && parentNamespace.getID() != Namespace.GLOBAL_NAMESPACE_ID) {
			fillListWithNamespacePath(parentNamespace, list);
		}
		list.add(namespace.getName());
	}

	@Override
	public String[] getPath() {
		lock.acquire();
		try {
			checkIsValid();
			ArrayList<String> list = new ArrayList<>();
			fillListWithNamespacePath(getParentNamespace(), list);
			list.add(getName());
			String[] path = list.toArray(new String[list.size()]);
			return path;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public int getReferenceCount() {
		lock.acquire();
		try {
			checkIsValid();
			ReferenceManager rm = symbolMgr.getReferenceManager();

			// if there is only one symbol, then all the references to this address count 
			if (hasExactlyOneSymbolAtAddress(address)) {
				return rm.getReferenceCountTo(address);
			}

			// search through references and see which ones apply specifically to this symbol
			ReferenceIterator iter = rm.getReferencesTo(address);
			int count = 0;
			boolean isPrimary = this.isPrimary();
			while (iter.hasNext()) {
				Reference ref = iter.next();
				long symbolID = ref.getSymbolID();
				// references refer to me if it matches my key or I'm primary and it doesn't
				// specify a specific symbol id
				if (symbolID == key || (isPrimary && symbolID < 0)) {
					count++;
				}
			}
			return count;
		}
		finally {
			lock.release();
		}
	}

	private boolean hasExactlyOneSymbolAtAddress(Address addr) {
		SymbolIterator it = symbolMgr.getSymbolsAsIterator(addr);
		if (!it.hasNext()) {
			return false;
		}
		it.next();
		return !it.hasNext();
	}

	@Override
	public Reference[] getReferences(TaskMonitor monitor) {
		lock.acquire();
		try {
			checkIsValid();
			if (monitor == null) {
				monitor = TaskMonitor.DUMMY;
			}

			if (monitor.getMaximum() == 0) {
				// If the monitor has not been initialized, then the progress will not correctly
				// display anything as setProgress() is called below.  We can't know what to
				// initialize to without counting all the references, which is as much work as
				// this method.
				monitor = new UnknownProgressWrappingTaskMonitor(monitor, 20);
			}

			ReferenceManager rm = symbolMgr.getReferenceManager();
			ReferenceIterator iter = rm.getReferencesTo(address);
			boolean isPrimary = this.isPrimary();
			ArrayList<Reference> list = new ArrayList<>();
			int cnt = 0;
			while (iter.hasNext()) {
				if (monitor.isCancelled()) {
					break; // return partial list
				}
				Reference ref = iter.next();
				long symbolID = ref.getSymbolID();
				if (symbolID == key || (isPrimary && symbolID < 0)) {
					list.add(ref);
					monitor.setProgress(cnt++);
				}
			}
			Reference[] refs = new Reference[list.size()];
			return list.toArray(refs);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Reference[] getReferences() {
		return getReferences(TaskMonitor.DUMMY);
	}

	@Override
	public boolean hasMultipleReferences() {
		lock.acquire();
		try {
			checkIsValid();
			ReferenceManager rm = symbolMgr.getReferenceManager();
			ReferenceIterator iter = rm.getReferencesTo(address);
			boolean isPrimary = this.isPrimary();
			int count = 0;
			while (iter.hasNext()) {
				Reference ref = iter.next();
				long symbolID = ref.getSymbolID();
				if (symbolID == key || (isPrimary && symbolID < 0)) {
					count++;
					if (count > 1) {
						return true;
					}
				}
			}
			return false;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean hasReferences() {
		lock.acquire();
		try {
			checkIsValid();
			ReferenceManager rm = symbolMgr.getReferenceManager();
			ReferenceIterator iter = rm.getReferencesTo(address);
			boolean isPrimary = this.isPrimary();
			while (iter.hasNext()) {
				Reference ref = iter.next();
				long symbolID = ref.getSymbolID();
				if (symbolID == key || (isPrimary && symbolID < 0)) {
					return true;
				}
			}
			return false;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean isDynamic() {
		return (record == null);
	}

	@Override
	public boolean isExternalEntryPoint() {
		lock.acquire();
		try {
			checkIsValid();
			return symbolMgr.isExternalEntryPoint(address);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public abstract boolean isPrimary();

	/**
	 * Sets this symbol's source as specified.
	 * @param newSource the new source type (IMPORTED, ANALYSIS, USER_DEFINED)
	 * @throws IllegalArgumentException if you try to change the source from default or to default
	 */
	@Override
	public void setSource(SourceType newSource) {
		lock.acquire();
		try {
			checkDeleted();
			symbolMgr.validateSource(getName(), getAddress(), getSymbolType(), newSource);
			SourceType oldSource = getSource();
			if (newSource == oldSource) {
				return;
			}
			if (newSource == SourceType.DEFAULT || oldSource == SourceType.DEFAULT) {
				String msg = "Can't change between DEFAULT and non-default symbol. Symbol is " +
					getName() + " @ " + getAddress().toString() + ".";
				throw new IllegalArgumentException(msg);
			}
			if (record != null) {
				setSourceFlagBit(newSource);
				updateRecord();
				symbolMgr.symbolSourceChanged(this);
			}
		}
		finally {
			lock.release();
		}
	}

	private void setSourceFlagBit(SourceType newSource) {
		byte flags = record.getByteValue(SymbolDatabaseAdapter.SYMBOL_FLAGS_COL);
		byte clearBits = SymbolDatabaseAdapter.SYMBOL_SOURCE_BITS;
		byte setBits = (byte) newSource.ordinal();
		flags &= ~clearBits;
		flags |= setBits;
		record.setByteValue(SymbolDatabaseAdapter.SYMBOL_FLAGS_COL, flags);
	}

	@Override
	public SourceType getSource() {
		lock.acquire();
		try {
			checkIsValid();
			if (record == null) {
				return SourceType.DEFAULT;
			}
			byte sourceBits = SymbolDatabaseAdapter.SYMBOL_SOURCE_BITS;
			byte flags = record.getByteValue(SymbolDatabaseAdapter.SYMBOL_FLAGS_COL);
			byte adapterSource = (byte) (flags & sourceBits);
			return SourceType.values()[adapterSource];
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean isPinned() {
		return false; //most symbols can't be pinned.
	}

	protected boolean doIsPinned() {
		lock.acquire();
		try {
			checkIsValid();
			if (record == null) {
				return false;
			}
			byte flags = record.getByteValue(SymbolDatabaseAdapter.SYMBOL_FLAGS_COL);
			return ((flags & SymbolDatabaseAdapter.SYMBOL_PINNED_FLAG) != 0);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setPinned(boolean pinned) {
		throw new UnsupportedOperationException("Only Code and Function Symbols may be pinned.");
	}

	protected void doSetPinned(boolean pinned) {
		lock.acquire();
		try {
			checkDeleted();
			if (pinned == isPinned()) {
				return;
			}
			if (record != null) {
				updatePinnedFlag(pinned);
				updateRecord();
				symbolMgr.symbolAnchoredFlagChanged(this);
			}
		}
		finally {
			lock.release();
		}
	}

	private void updatePinnedFlag(boolean pinned) {
		byte flags = record.getByteValue(SymbolDatabaseAdapter.SYMBOL_FLAGS_COL);
		if (pinned) {
			flags |= SymbolDatabaseAdapter.SYMBOL_PINNED_FLAG;
		}
		else {
			flags &= ~SymbolDatabaseAdapter.SYMBOL_PINNED_FLAG;
		}
		record.setByteValue(SymbolDatabaseAdapter.SYMBOL_FLAGS_COL, flags);
	}

	@Override
	public void setName(String newName, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		try {
			setNameAndNamespace(newName, getParentNamespace(), source);
		}
		catch (CircularDependencyException e) {
			// can't happen since we are only changing the name and not the namespace
		}
	}

	@Override
	public void setNamespace(Namespace newNamespace)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {

		setNameAndNamespace(getName(), newNamespace, getSource());
	}

	/**
	 * Allow symbol implementations to validate the source when setting the name of
	 * this symbol
	 * 
	 * @param newName the new name 
	 * @param source the source type
	 * @return the validated source type
	 */
	protected SourceType validateNameSource(String newName, SourceType source) {
		return source;
	}

	public void doSetNameAndNamespace(String newName, Namespace newNamespace, SourceType source,
			boolean checkForDuplicates)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {

		lock.acquire();
		try {
			checkDeleted();
			checkEditOK();

			source = validateNameSource(newName, source);

			symbolMgr.validateSource(newName, getAddress(), getSymbolType(), source);

			Namespace oldNamespace = getParentNamespace();
			boolean namespaceChange = !oldNamespace.equals(newNamespace);
			if (namespaceChange) {
				if (!isValidParent(newNamespace)) {
					throw new InvalidInputException("Namespace \"" + newNamespace.getName(true) +
						"\" is not valid for symbol " + getName());
				}
				if (isDescendant(newNamespace)) {
					throw new CircularDependencyException("Namespace \"" +
						newNamespace.getName(true) + "\" is a descendant of symbol " + getName());
				}
			}

			boolean nameChange = true;
			String oldName = getName();
			SourceType oldSource = getSource();
			if (source == SourceType.DEFAULT) {
				if (getSource() == SourceType.DEFAULT && !namespaceChange) {
					return;
				}
				newName = "";
			}
			else {
				SymbolUtilities.validateName(newName);
				nameChange = !oldName.equals(newName);
				if (!namespaceChange && !nameChange) {
					return;
				}

				if (checkForDuplicates) {
					symbolMgr.checkDuplicateSymbolName(address, newName, newNamespace,
						getSymbolType());
				}
			}

			if (record != null) {

				List<SymbolDB> dynamicallyRenamedSymbols = getSymbolsDynamicallyRenamedByMyRename();
				List<String> oldDynamicallyRenamedSymbolNames = null;
				if (dynamicallyRenamedSymbols != null) {
					oldDynamicallyRenamedSymbolNames =
						new ArrayList<>(dynamicallyRenamedSymbols.size());
					for (Symbol s : dynamicallyRenamedSymbols) {
						oldDynamicallyRenamedSymbolNames.add(s.getName());
					}
				}

				record.setLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_COL, newNamespace.getID());
				record.setString(SymbolDatabaseAdapter.SYMBOL_NAME_COL, newName);
				updateSymbolSource(record, source);
				updateRecord();
				cachedName = null;  // we can't clear it until now, since any call to getName()
									// will cause the cached name to reset to the old name
				if (namespaceChange) {
					symbolMgr.symbolNamespaceChanged(this, oldNamespace);
				}
				if (nameChange) {
					SymbolType symbolType = getSymbolType();
					if (isExternal() &&
						(symbolType == SymbolType.FUNCTION || symbolType == SymbolType.LABEL)) {
						ExternalManagerDB externalManager = symbolMgr.getExternalManager();
						ExternalLocationDB externalLocation =
							(ExternalLocationDB) externalManager.getExternalLocation(this);
						externalLocation.saveOriginalNameIfNeeded(oldNamespace, oldName, oldSource);
					}
					symbolMgr.symbolRenamed(this, oldName);
					if (dynamicallyRenamedSymbols != null) {
						ProgramDB program = symbolMgr.getProgram();
						for (int i = 0; i < dynamicallyRenamedSymbols.size(); i++) {
							Symbol s = dynamicallyRenamedSymbols.get(i);
							program.symbolChanged(s, ChangeManager.DOCR_SYMBOL_RENAMED,
								s.getAddress(), s, oldDynamicallyRenamedSymbolNames.get(i),
								s.getName());
						}
					}
				}
			}
			else {
				symbolMgr.convertDynamicSymbol(this, newName, newNamespace.getID(), source);
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setNameAndNamespace(String newName, Namespace newNamespace, SourceType source)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {

		doSetNameAndNamespace(newName, newNamespace, source, true);
	}

	protected List<SymbolDB> getSymbolsDynamicallyRenamedByMyRename() {
		return null;
	}

	private void checkEditOK() throws InvalidInputException {
		if (getSymbolType() == SymbolType.LABEL) {
			for (Register reg : symbolMgr.getProgram().getRegisters(getAddress())) {
				if (reg.getName().equals(getName())) {
					throw new InvalidInputException("Register symbol may not be renamed");
				}
			}
		}
	}

	private void updateSymbolSource(DBRecord symbolRecord, SourceType source) {
		byte flags = record.getByteValue(SymbolDatabaseAdapter.SYMBOL_FLAGS_COL);
		flags &= ~SymbolDatabaseAdapter.SYMBOL_SOURCE_BITS;
		flags |= (byte) source.ordinal();
		symbolRecord.setByteValue(SymbolDatabaseAdapter.SYMBOL_FLAGS_COL, flags);
	}

	/**
	 * @see ghidra.program.model.symbol.Symbol#setPrimary()
	 */
	@Override
	public boolean setPrimary() {
		return false;
	}

	@Override
	public long getID() {
		return key;
	}

	@Override
	public boolean equals(Object obj) {
		if ((obj == null) || (!(obj instanceof Symbol))) {
			return false;
		}
		if (obj == this) {
			return true;
		}

		Symbol s = (Symbol) obj;
		if (hasSameId(s)) {
			return true;
		}

		if (!getName().equals(s.getName())) {
			return false;
		}

		if (!getAddress().equals(s.getAddress())) {
			return false;
		}
		if (!getSymbolType().equals(s.getSymbolType())) {
			return false;
		}
		Symbol myParent = getParentSymbol();
		Symbol otherParent = s.getParentSymbol();

		return SystemUtilities.isEqual(myParent, otherParent);
	}

	private boolean hasSameId(Symbol s) {
		if (getID() == s.getID()) {
			return getProgram() == s.getProgram();
		}
		return false;
	}

	@Override
	public int hashCode() {
		return (int) key;
	}

	private void updateRecord() {
		try {
			symbolMgr.getDatabaseAdapter().updateSymbolRecord(record);
		}
		catch (IOException e) {
			symbolMgr.dbError(e);
		}
	}

	@Override
	public Namespace getParentNamespace() {
		return doGetParentNamespace();
	}

	protected Namespace doGetParentNamespace() {
		Symbol parent = getParentSymbol();
		if (parent != null) {
			return (Namespace) parent.getObject();
		}
		return symbolMgr.getProgram().getGlobalNamespace();
	}

	@Override
	public Symbol getParentSymbol() {
		lock.acquire();
		try {
			checkIsValid();
			if (record == null) {
				return null;
			}
			return symbolMgr.getSymbol(
				record.getLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_COL));
		}
		finally {
			lock.release();
		}
	}

	long getParentID() {
		lock.acquire();
		try {
			checkIsValid();
			if (record == null) {
				return Namespace.GLOBAL_NAMESPACE_ID;
			}
			return record.getLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_COL);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean isGlobal() {
		lock.acquire();
		try {
			checkIsValid();
			if (record == null) {
				return true;
			}
			return record.getLongValue(
				SymbolDatabaseAdapter.SYMBOL_PARENT_COL) == Namespace.GLOBAL_NAMESPACE_ID;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Returns the symbol's string data which has different meanings depending on the symbol type
	 * and whether or not it is external
	 * @return the symbol's string data
	 */
	public String getSymbolStringData() {
		lock.acquire();
		try {
			checkIsValid();
			if (record == null) {
				return null;
			}
			return record.getString(SymbolDatabaseAdapter.SYMBOL_STRING_DATA_COL);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Sets the symbol's string data field. This field's data has different uses depending on the 
	 * symbol type and whether or not it is external. 
	 * @param stringData the string to store in the string data field
	 */
	public void setSymbolStringData(String stringData) {
		lock.acquire();
		try {
			checkDeleted();
			if (record == null) {
				return;
			}
			String oldData = record.getString(SymbolDatabaseAdapter.SYMBOL_STRING_DATA_COL);
			if (Objects.equals(stringData, oldData)) {
				return;
			}
			record.setString(SymbolDatabaseAdapter.SYMBOL_STRING_DATA_COL, stringData);
			updateRecord();
			symbolMgr.symbolDataChanged(this);
		}
		finally {
			lock.release();
		}
	}

	protected void removeAllReferencesTo() {
		ReferenceManager refMgr = symbolMgr.getReferenceManager();
		ReferenceIterator it = refMgr.getReferencesTo(address);
		while (it.hasNext()) {
			Reference ref = it.next();
			refMgr.delete(ref);
		}
	}

	public long getDataTypeId() {
		lock.acquire();
		try {
			checkIsValid();
			if (record != null) {
				Field value = record.getFieldValue(SymbolDatabaseAdapter.SYMBOL_DATATYPE_COL);
				if (value.isNull()) {
					return -1;
				}
				return value.getLongValue();
			}
			return -1;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Sets the generic symbol data 1.
	 * @param value the value to set as symbol data 1.
	 */
	public void setDataTypeId(long value) {
		lock.acquire();
		try {
			checkDeleted();
			if (record != null) {
				record.setLongValue(SymbolDatabaseAdapter.SYMBOL_DATATYPE_COL, value);
				updateRecord();
				symbolMgr.symbolDataChanged(this);
			}
		}
		finally {
			lock.release();
		}
	}

	/**
	 * gets the generic symbol data 2 data.
	 * @return the symbol data
	 */
	protected int getVariableOffset() {
		lock.acquire();
		try {
			checkIsValid();
			if (record != null) {
				return record.getIntValue(SymbolDatabaseAdapter.SYMBOL_VAROFFSET_COL);
			}
			return 0;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Sets the symbol's variable offset. For parameters, this is the ordinal, for locals, it is 
	 * the first use offset
	 * @param offset the value to set as the symbols variable offset. 
	 */
	public void setVariableOffset(int offset) {
		lock.acquire();
		try {
			checkDeleted();
			if (record != null) {
				record.setIntValue(SymbolDatabaseAdapter.SYMBOL_VAROFFSET_COL, offset);
				updateRecord();
				symbolMgr.symbolDataChanged(this);
			}
		}
		finally {
			lock.release();
		}
	}

	protected void doSetPrimary(boolean primary) {
		lock.acquire();
		try {
			checkDeleted();
			if (record != null) {
				if (primary) {
					long addrKey = record.getLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL);
					record.setLongValue(SymbolDatabaseAdapter.SYMBOL_PRIMARY_COL, addrKey);
				}
				else {
					record.setField(SymbolDatabaseAdapter.SYMBOL_PRIMARY_COL, null);
				}
				updateRecord();
				symbolMgr.symbolDataChanged(this);
			}
		}
		finally {
			lock.release();
		}

	}

	protected boolean doCheckIsPrimary() {
		lock.acquire();
		try {
			checkIsValid();
			if (record != null) {
				return !record.getFieldValue(SymbolDatabaseAdapter.SYMBOL_PRIMARY_COL).isNull();
			}
			return false;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean delete() {
		lock.acquire();
		isDeleting = true;
		try {
			if (checkIsValid() && record != null) {
				return symbolMgr.doRemoveSymbol(this);
			}
		}
		finally {
			isDeleting = false;
			lock.release();
		}
		return false;
	}

	public boolean isDeleting() {
		return isDeleting;
	}

	@Override
	public boolean isDescendant(Namespace namespace) {
		if (this == namespace.getSymbol()) {
			return true;
		}
		Namespace parent = namespace.getParentNamespace();
		while (parent != null) {
			Symbol s = parent.getSymbol();
			if (this.equals(s)) {
				return true;
			}
			parent = parent.getParentNamespace();
		}

		return false;
	}

	@Override
	public abstract boolean isValidParent(Namespace parent);

	/**
	 * Change the record and key associated with this symbol
	 * @param record the record
	 */
	void setRecord(DBRecord record) {
		this.record = record;
		keyChanged(record.getKey());
	}
}
