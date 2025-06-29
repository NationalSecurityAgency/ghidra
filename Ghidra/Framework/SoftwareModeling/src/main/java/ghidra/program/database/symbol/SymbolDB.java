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
import java.util.ArrayList;
import java.util.List;

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
import ghidra.program.util.ProgramEvent;
import ghidra.util.Lock;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Base class for symbols
 */
public abstract class SymbolDB extends DatabaseObject implements Symbol {

	private boolean isDeleting = false;

	protected DBRecord record;
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
			if (rec == null || record.getByteValue(SymbolDatabaseAdapter.SYMBOL_TYPE_COL) != rec
					.getByteValue(SymbolDatabaseAdapter.SYMBOL_TYPE_COL)) {
				return false;
			}
			record = rec;
			address = symbolMgr.getAddressMap()
					.decodeAddress(rec.getLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL));
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
		program.symbolChanged(this, ProgramEvent.SYMBOL_ADDRESS_CHANGED, oldAddr, this, oldAddr,
			addr);
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

	private void fillListWithNamespacePath(Namespace namespace, List<String> list) {
		if (namespace == null || namespace.getID() == Namespace.GLOBAL_NAMESPACE_ID) {
			// we don't include the global namespace name in the path
			return;
		}
		Namespace parentNamespace = namespace.getParentNamespace();
		if (parentNamespace != null) {
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
	public boolean isDynamic() {
		return (record == null);
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

	protected void setSourceFlagBit(SourceType newSource) {
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

			SymbolType type = getSymbolType();

			symbolMgr.checkValidNamespaceArgument(newNamespace);

			source = validateNameSource(newName, source);

			symbolMgr.validateSource(newName, getAddress(), type, source);

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
					symbolMgr.checkDuplicateSymbolName(address, newName, newNamespace, type);
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

				record.setLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_ID_COL,
					newNamespace.getID());
				record.setString(SymbolDatabaseAdapter.SYMBOL_NAME_COL, newName);
				updateSymbolSource(record, source);
				updateRecord();
				cachedName = null;  // we can't clear it until now, since any call to getName()
									// will cause the cached name to reset to the old name
				if (namespaceChange) {
					symbolMgr.symbolNamespaceChanged(this, oldNamespace);
				}
				if (nameChange) {
					if (isExternal() && (type == SymbolType.FUNCTION || type == SymbolType.LABEL)) {
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
							program.symbolChanged(s, ProgramEvent.SYMBOL_RENAMED, s.getAddress(), s,
								oldDynamicallyRenamedSymbolNames.get(i), s.getName());
						}
					}
				}

				if (type == SymbolType.NAMESPACE || type == SymbolType.CLASS) {
					// function class structure path change may impact auto-params
					symbolMgr.getProgram().getFunctionManager().invalidateCache(true);
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

	protected void updateRecord() {
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
			return symbolMgr
					.getSymbol(record.getLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_ID_COL));
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
			return record.getLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_ID_COL);
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
				SymbolDatabaseAdapter.SYMBOL_PARENT_ID_COL) == Namespace.GLOBAL_NAMESPACE_ID;
		}
		finally {
			lock.release();
		}
	}

	public long getDataTypeId() {
		validate(lock);
		// record always present when use of datatype ID is supported (i.e., external location)
		Field value = record.getFieldValue(SymbolDatabaseAdapter.SYMBOL_DATATYPE_COL);
		if (value.isNull()) {
			return -1;
		}
		return value.getLongValue();
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
	public boolean isValidParent(Namespace parent) {
		return symbolMgr.isMyNamespace(parent);
	}

	/**
	 * Change the record and key associated with this symbol
	 * @param record the record
	 */
	void setRecord(DBRecord record) {
		this.record = record;
		keyChanged(record.getKey());
	}

}
