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
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

import db.*;
import ghidra.program.database.*;
import ghidra.program.database.code.CodeManager;
import ghidra.program.database.external.ExternalManagerDB;
import ghidra.program.database.function.FunctionManagerDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.references.ReferenceDBManager;
import ghidra.program.database.util.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.LanguageTranslator;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class SymbolManager implements SymbolTable, ManagerDB {

	private static final String OLD_LOCAL_SYMBOLS_TABLE = "OldLocalSymbols";
	private static final int OLD_SYMBOL_ADDR_COL = 0;
	private static final int OLD_SYMBOL_NAME_COL = 1;
	private static final int OLD_SYMBOL_IS_PRIMARY_COL = 2;
	private static final Schema OLD_LOCAL_SYMBOLS_SCHEMA = new Schema(0, "ID",
		new Field[] { LongField.INSTANCE, StringField.INSTANCE, BooleanField.INSTANCE },
		new String[] { "OldAddress", "Name", "IsPrimary" });

	static final String OLD_EXTERNAL_ENTRY_TABLE_NAME = "External Entries";

	// this is used to map dynamic symbol ids to address.  Using 0x40 in the high order bits
	// of the id prevents it from colliding with ids that are allocated starting at 0.
	static final Byte DYNAMIC_ADDRESS_MAP_ID = (byte) 0x40;

	private AddressMap addrMap;
	private SymbolDatabaseAdapter adapter;
	private LabelHistoryAdapter historyAdapter;

	private DBObjectCache<SymbolDB> cache;
	private ProgramDB program;
	private ReferenceDBManager refManager;
	private NamespaceManager namespaceMgr;
	private VariableStorageManagerDB variableStorageMgr;

	private OldVariableStorageManagerDB oldVariableStorageMgr; // required for upgrade

	private AddressMapImpl dynamicSymbolAddressMap;

	private Lock lock;
	final static Symbol[] NO_SYMBOLS = new SymbolDB[0];

	/**
	 * Creates a new Symbol manager.
	 * @param handle the database handler
	 * @param addrMap the address map.
	 * @param openMode the open mode.
	 * @param lock the program synchronization lock
	 * @param monitor the progress monitor used when upgrading.
	 * @throws CancelledException if the user cancels the upgrade.
	 * @throws IOException if a database io error occurs.
	 * @throws VersionException if the database version doesn't match the current version.
	 */
	public SymbolManager(DBHandle handle, AddressMap addrMap, int openMode, Lock lock,
			TaskMonitor monitor) throws CancelledException, IOException, VersionException {

		this.addrMap = addrMap;
		this.lock = lock;
		dynamicSymbolAddressMap = new AddressMapImpl((byte) 0x40, addrMap.getAddressFactory());
		initializeAdapters(handle, openMode, monitor);
		cache = new DBObjectCache<>(100);

		variableStorageMgr = new VariableStorageManagerDB(handle, addrMap, openMode, lock, monitor);

		if (openMode == DBConstants.UPGRADE &&
			OldVariableStorageManagerDB.isOldVariableStorageManagerUpgradeRequired(handle)) {
			oldVariableStorageMgr = new OldVariableStorageManagerDB(handle, addrMap, monitor);
		}
	}

	private void initializeAdapters(DBHandle handle, int openMode, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		VersionException versionExc = null;
		try {
			adapter = SymbolDatabaseAdapter.getAdapter(handle, openMode, addrMap, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			historyAdapter = LabelHistoryAdapter.getAdapter(handle, openMode, addrMap, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		if (versionExc != null) {
			throw versionExc;
		}
	}

	/**
	 * Find previously defined variable storage address
	 * @param storage variable storage
	 * @return previously defined variable storage address or null if not found
	 * @throws IOException if there is database exception
	 */
	public Address findVariableStorageAddress(VariableStorage storage) throws IOException {
		return variableStorageMgr.getVariableStorageAddress(storage, false);
	}

	@Override
	public void setProgram(ProgramDB program) {
		this.program = program;
		refManager = (ReferenceDBManager) program.getReferenceManager();
		namespaceMgr = program.getNamespaceManager();
		variableStorageMgr.setProgram(program);
	}

	@Override
	public void programReady(int openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {

		if (openMode == DBConstants.UPGRADE) {
			processOldLocalSymbols(monitor);
			processOldExternalEntryPoints(monitor);

			if (currentRevision < ProgramDB.ADDED_VARIABLE_STORAGE_MANAGER_VERSION) {
				// Eliminated namespace encoding within External address encoding
				// see OldGenericNamespaceAddress
				upgradeOldNamespaceAddresses(monitor);
				// Migrate all other OldNamespaceAddresses used for variable symbols
				processOldVariableAddresses(monitor);
			}
			if (currentRevision < ProgramDB.EXTERNAL_FUNCTIONS_ADDED_VERSION) {
				// SymbolType.EXTERNAL eliminated with program revision 17
				processOldExternalTypes(monitor);
			}

			if (oldVariableStorageMgr != null) {
				// migrate from old variable storage table which utilized namespace-specific
				// storage addresses
				migrateFromOldVariableStorageManager(monitor);
			}
			else if (currentRevision == ProgramDB.COMPOUND_VARIABLE_STORAGE_ADDED_VERSION) {
				// Revised (2nd) VariableStorageManager was already added but we may have forgotten
				// to migrate old register variable addresses if previously upgraded from
				// older than program version 10
				processOldVariableAddresses(monitor);
			}
		}
	}

	/**
	 * Check for and upgrade old namespace symbol addresses which included a namespace ID.
	 * Start at end since Namespace-0 will not result in an OldGenericNamespaceAddress.
	 * Namespace-0 external symbols do not need to be upgraded since this is effectively
	 * where all the moved external addresses will be placed.
	 * The triggering of this upgrade relies on the addition of the VariableManager which
	 * trigger an upgrade.
	 * @param monitor the task monitor
	 */
	private boolean upgradeOldNamespaceAddresses(TaskMonitor monitor)
			throws IOException, CancelledException {

		ReferenceDBManager refMgr = (ReferenceDBManager) program.getReferenceManager();

		Address nextExtAddr = getNextExternalSymbolAddress();

		Symbol[] syms = getSymbols(Address.NO_ADDRESS);
		for (Symbol sym : syms) {
			SymbolDB libSym = (SymbolDB) sym;
			if (libSym.getSymbolType() != SymbolType.LIBRARY) {
				continue;
			}
			monitor.setMessage("Processing Old External Addresses...");
			monitor.initialize(1);
			RecordIterator recIter = adapter.getSymbolsByNamespace(libSym.getID());
			while (recIter.hasNext()) {
				DBRecord rec = recIter.next();
				Address oldAddr =
					addrMap.decodeAddress(rec.getLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL));
				if (!(oldAddr instanceof OldGenericNamespaceAddress)) {
					continue;
				}
				moveSymbolsAt(oldAddr, nextExtAddr);
				refMgr.moveReferencesTo(oldAddr, nextExtAddr, monitor);
				nextExtAddr = nextExtAddr.next();
			}
		}

		return true;
	}

	private void processOldExternalTypes(TaskMonitor monitor)
			throws IOException, CancelledException {

		monitor.setMessage("Migrating External Symbols...");
		monitor.initialize(1); // don't know how many external symbols - should not be too many to matter

		RecordIterator symbolRecordIterator =
			adapter.getSymbols(AddressSpace.EXTERNAL_SPACE.getMinAddress(),
				AddressSpace.EXTERNAL_SPACE.getMaxAddress(), true);
		while (symbolRecordIterator.hasNext()) {
			monitor.checkCanceled();
			DBRecord rec = symbolRecordIterator.next();
			rec.setByteValue(SymbolDatabaseAdapter.SYMBOL_TYPE_COL, SymbolType.LABEL.getID());
			adapter.updateSymbolRecord(rec);
		}
		monitor.setProgress(1);
	}

	/**
	 * Upgrade old stack and register variable symbol address to variable addresses.
	 * Also force associated references to be updated to new variable addresses.
	 * @param monitor the task monitor
	 * @throws IOException if there is database exception
	 * @throws CancelledException if the operation is cancelled
	 */
	private void processOldVariableAddresses(TaskMonitor monitor)
			throws IOException, CancelledException {

		monitor.setMessage("Upgrading Variable Symbols...");
		monitor.initialize(adapter.getSymbolCount());
		int cnt = 0;

		Table table = adapter.getTable();

		RecordIterator symbolRecordIterator = adapter.getSymbols();
		while (symbolRecordIterator.hasNext()) {
			monitor.checkCanceled();
			monitor.setProgress(++cnt);
			DBRecord rec = symbolRecordIterator.next();
			long addr = rec.getLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL);
			Address oldAddress = addrMap.decodeAddress(addr);
			if (!(oldAddress instanceof OldGenericNamespaceAddress)) {
				continue; // added by function manager upgrade
			}
			byte typeID = rec.getByteValue(SymbolDatabaseAdapter.SYMBOL_TYPE_COL);
			SymbolType type = SymbolType.getSymbolType(typeID);
			if (type != SymbolType.LOCAL_VAR && type != SymbolType.PARAMETER &&
				type != SymbolType.GLOBAL_VAR) {
				continue;
			}

			Address storageAddr = oldAddress.getNewAddress(oldAddress.getOffset());

			// move variable references - eliminate variable symbol bindings no longer supported
			refManager.moveReferencesTo(oldAddress, storageAddr, monitor);

			try {
				Address variableAddr = getUpgradedVariableAddress(storageAddr,
					rec.getLongValue(SymbolDatabaseAdapter.SYMBOL_DATATYPE_COL));

				// fix symbol address
				rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL,
					addrMap.getKey(variableAddr, true));
				table.putRecord(rec); // symbol key is preserved
			}
			catch (InvalidInputException e) {
				Symbol parent =
					getSymbol(rec.getLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_COL));
				Msg.warn(this, "Variable symbol upgrade problem: " + parent.getName() + ":" +
					rec.getString(SymbolDatabaseAdapter.SYMBOL_NAME_COL));
			}
		}
	}

	/**
	 * No more sharing the same variable address for multiple variable symbols.
	 * Must split these up.  Only reference to variable addresses should be the
	 * symbol address - reference refer to physical/stack addresses, and symbolIDs.
	 * @param monitor the task monitor
	 * @throws CancelledException if the operation is cancelled
	 */
	public void migrateFromOldVariableStorageManager(TaskMonitor monitor)
			throws CancelledException {
		try {
			Address maxAddr = getMaxSymbolAddress(AddressSpace.VARIABLE_SPACE);
			if (maxAddr == null) {
				oldVariableStorageMgr.deleteTable();
				oldVariableStorageMgr = null;
				return;
			}
			RecordIterator recIter =
				adapter.getSymbols(AddressSpace.VARIABLE_SPACE.getMinAddress(), maxAddr, true);
			Address newVarAddr = null;
			Address curVarAddr = null;
			long curDataTypeId = -1;
			while (recIter.hasNext()) {
				monitor.checkCanceled();
				DBRecord rec = recIter.next();
				Address addr =
					addrMap.decodeAddress(rec.getLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL));
				if (!addr.isVariableAddress()) {
					throw new RuntimeException("Unexpected");
				}

				long dataTypeId = rec.getLongValue(SymbolDatabaseAdapter.SYMBOL_DATATYPE_COL);

				if (curVarAddr == null || !addr.equals(curVarAddr) || dataTypeId != curDataTypeId) {

					curVarAddr = addr;
					curDataTypeId = rec.getLongValue(SymbolDatabaseAdapter.SYMBOL_DATATYPE_COL);

					Address storageAddr = oldVariableStorageMgr.getStorageAddress(addr);

					try {
						newVarAddr = getUpgradedVariableAddress(storageAddr, curDataTypeId);
					}
					catch (InvalidInputException e) {
						Symbol parent =
							getSymbol(rec.getLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_COL));
						Msg.warn(this, "Variable symbol upgrade problem: " + parent.getName() +
							":" + rec.getString(SymbolDatabaseAdapter.SYMBOL_NAME_COL));
						curVarAddr = null;
						newVarAddr = variableStorageMgr.getVariableStorageAddress(
							VariableStorage.BAD_STORAGE, true);
					}
				}

				rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL,
					addrMap.getKey(newVarAddr, true));
				adapter.updateSymbolRecord(rec);
			}

			oldVariableStorageMgr.deleteTable();
			oldVariableStorageMgr = null;
		}
		catch (IOException e) {
			dbError(e);
		}
	}

	private Address getUpgradedVariableAddress(Address storageAddr, long dataTypeId)
			throws InvalidInputException, IOException {
		// Let the variable do the work
		DataType dt = getDataType(dataTypeId);
		Variable var = new LocalVariableImpl(null, 0, dt, storageAddr, program);
		return variableStorageMgr.getVariableStorageAddress(var.getVariableStorage(), true);
	}

	/**
	 * Create memory references for the external entry points; then delete the table.
	 */
	private void processOldExternalEntryPoints(TaskMonitor monitor)
			throws IOException, CancelledException {
		Table table = program.getDBHandle().getTable(OLD_EXTERNAL_ENTRY_TABLE_NAME);
		if (table == null) {
			return;
		}

		AddressMap oldAddrMap = addrMap.getOldAddressMap();

		monitor.setMessage("Upgrading External Entry Points...");
		monitor.initialize(table.getRecordCount());
		int cnt = 0;

		RecordIterator iter = table.iterator();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			DBRecord rec = iter.next();
			Address addr = oldAddrMap.decodeAddress(rec.getKey());
			refManager.addExternalEntryPointRef(addr);
			monitor.setProgress(++cnt);
		}

		program.getDBHandle().deleteTable(OLD_EXTERNAL_ENTRY_TABLE_NAME);
	}

	/**
	 * Add old local symbols
	 * @throws IOException if there is database exception
	 * @throws CancelledException if the operation is cancelled
	 */
	private void processOldLocalSymbols(TaskMonitor monitor)
			throws IOException, CancelledException {
		Table table = program.getDBHandle().getScratchPad().getTable(OLD_LOCAL_SYMBOLS_TABLE);
		if (table == null) {
			return;
		}

		AddressMap oldAddrMap = addrMap.getOldAddressMap();

		monitor.setMessage("Upgrading Local Symbols...");
		monitor.initialize(table.getRecordCount());
		int cnt = 0;

		RecordIterator iter = table.iterator();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			DBRecord rec = iter.next();
			Address addr = oldAddrMap.decodeAddress(rec.getLongValue(OLD_SYMBOL_ADDR_COL));
			Namespace namespace = namespaceMgr.getNamespaceContaining(addr);
			if (namespace.getID() != Namespace.GLOBAL_NAMESPACE_ID) {
				// Add symbol to function namespace
				String name = rec.getString(OLD_SYMBOL_NAME_COL);
				if (SymbolUtilities.startsWithDefaultDynamicPrefix(name)) {
					name = "_" + name; // dynamic prefix is reserved
				}
				boolean success = false;
				while (!success) {
					try {
						addSymbolRecord(rec.getKey(), addr, namespace, name,
							rec.getBooleanValue(OLD_SYMBOL_IS_PRIMARY_COL), SymbolType.LABEL,
							SourceType.USER_DEFINED);
						success = true;
					}
					catch (DuplicateNameException e) {
						name = rec.getString(OLD_SYMBOL_NAME_COL) + (++cnt);
					}
				}
			}
			monitor.setProgress(++cnt);
		}
	}

	/**
	 * Save off old local symbols whose upgrade needs to be deferred until after function manager
	 * upgrade has been completed.
	 * @param tmpHandle scratch pad database handle
	 * @param symbolID local symbol ID
	 * @param oldAddr old address value from symbol table
	 * @param name symbol name
	 * @param isPrimary true if symbol is primary at oldAddr
	 * @throws IOException if there is database exception
	 */
	static void saveLocalSymbol(DBHandle tmpHandle, long symbolID, long oldAddr, String name,
			boolean isPrimary) throws IOException {
		Table table = tmpHandle.getTable(OLD_LOCAL_SYMBOLS_TABLE);
		if (table == null) {
			table = tmpHandle.createTable(OLD_LOCAL_SYMBOLS_TABLE, OLD_LOCAL_SYMBOLS_SCHEMA);
		}
		DBRecord rec = OLD_LOCAL_SYMBOLS_SCHEMA.createRecord(symbolID);
		rec.setLongValue(OLD_SYMBOL_ADDR_COL, oldAddr);
		rec.setString(OLD_SYMBOL_NAME_COL, name);
		rec.setBooleanValue(OLD_SYMBOL_IS_PRIMARY_COL, isPrimary);
		table.putRecord(rec);
	}

	void checkDuplicateSymbolName(Address addr, String name, Namespace namespace, SymbolType type)
			throws DuplicateNameException {

		if (addr.isMemoryAddress() && getSymbol(name, addr, namespace) != null) {
			throw new DuplicateNameException(
				"A symbol named " + name + " already exists at this address!");
		}

		if (name.length() == 0) {
			return;
		}

		if (type.allowsDuplicates()) {
			return;
		}

		Symbol symbol = getFirstSymbol(name, namespace, s -> !s.getSymbolType().allowsDuplicates());
		if (symbol != null) {
			throw new DuplicateNameException(
				"A " + symbol.getSymbolType() + " symbol with name " + name +
					" already exists in namespace " + symbol.getParentNamespace().getName());
		}
	}

	/*
	 * Convert the specified dynamic symbol to a named symbol. Both symbol removed and symbol added
	 * notifications are performed, although the symbol instance is changed and continues to be
	 * valid.
	 */
	void convertDynamicSymbol(SymbolDB symbol, String newName, long newParentID,
			SourceType source) {
		if (source == SourceType.DEFAULT) {
			String msg = "Can't rename dynamic symbol '" + symbol.getName() +
				"' and set its new source to DEFAULT.";
			throw new IllegalArgumentException(msg);
		}
		lock.acquire();
		try {
			long oldKey = symbol.getKey();
			Address address = symbol.getAddress();
			symbolRemoved(symbol, address, symbol.getName(), oldKey, Namespace.GLOBAL_NAMESPACE_ID,
				null);
			DBRecord record =
				adapter.createSymbol(newName, address, newParentID, SymbolType.LABEL, null,
					null, null, source, true);
			symbol.setRecord(record);
			symbolAdded(symbol);
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
	}

	SymbolDB getFunctionSymbol(Namespace namespace) {
		if (namespace.getID() == Namespace.GLOBAL_NAMESPACE_ID) {
			return null;
		}
		SymbolDB symbol = (SymbolDB) namespace.getSymbol();
		while (true) {
			if (symbol.getSymbolType() == SymbolType.FUNCTION) {
				return symbol;
			}
			if (symbol.getParentID() == Namespace.GLOBAL_NAMESPACE_ID) {
				break;
			}
			symbol = (SymbolDB) symbol.getParentSymbol();
		}
		return null;
	}

	private void addSymbolRecord(long symbolID, Address addr, Namespace namespace, String name,
			boolean isPrimary, SymbolType type, SourceType source)
			throws DuplicateNameException, IOException {

		if (getSymbol(symbolID) != null) {
			// This should not happen
			throw new IllegalArgumentException("Duplicate symbol ID");
		}
		checkDuplicateSymbolName(addr, name, namespace, type);

		DBRecord rec = SymbolDatabaseAdapter.SYMBOL_SCHEMA.createRecord(symbolID);
		rec.setString(SymbolDatabaseAdapter.SYMBOL_NAME_COL, name);
		long addressKey = addrMap.getKey(addr, true);
		rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL, addressKey);
		rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_COL, namespace.getID());
		rec.setByteValue(SymbolDatabaseAdapter.SYMBOL_TYPE_COL, type.getID());
		if (isPrimary) {
			rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_PRIMARY_COL, addressKey);
		}
		rec.setByteValue(SymbolDatabaseAdapter.SYMBOL_FLAGS_COL, (byte) source.ordinal());

		adapter.updateSymbolRecord(rec);
	}

	private SymbolDB makeSymbol(Address addr, DBRecord record, SymbolType type) {
		if (addr == null) {
			addr =
				addrMap.decodeAddress(record.getLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL));
		}
		if (type == SymbolType.CLASS) {
			return new ClassSymbol(this, cache, addr, record);
		}
		else if (type == SymbolType.LABEL) {
			return new CodeSymbol(this, cache, addr, record);
		}
		else if (type == SymbolType.NAMESPACE) {
			return new NamespaceSymbol(this, cache, addr, record);
		}
		else if (type == SymbolType.FUNCTION) {
			return new FunctionSymbol(this, cache, addr, record);
		}
		else if (type == SymbolType.LIBRARY) {
			return new LibrarySymbol(this, cache, addr, record);
		}
		else if (type == SymbolType.PARAMETER || type == SymbolType.LOCAL_VAR) {
			return new VariableSymbolDB(this, cache, type, variableStorageMgr, addr, record);
		}
		else if (type == SymbolType.GLOBAL_VAR) {
// TODO: Should this be a variable symbol which can return a variable ??
			return new GlobalRegisterSymbol(this, cache, addr, record);
		}
		throw new IllegalArgumentException("No symbol type for " + type);
	}

	@Override
	public int getNumSymbols() {
		return adapter.getSymbolCount();
	}

	@Override
	public boolean removeSymbolSpecial(Symbol sym) {
		lock.acquire();
		try {
			if (sym.getSymbolType() == SymbolType.FUNCTION) {
				Address addr = sym.getAddress();
				Function f = (Function) sym.getObject();
				Symbol nextPrimary = findFirstNonPrimarySymbol(addr);
				String name;
				Namespace parentNamespace;
				SourceType source;
				if (nextPrimary == null) {
					if (sym.getSource() == SourceType.DEFAULT) {
						return false; // Can't remove default function symbol.
					}
					name = SymbolUtilities.getDefaultFunctionName(addr);
					parentNamespace = getProgram().getGlobalNamespace();
					source = SourceType.DEFAULT;
				}
				else {
					// Absorb another symbol.
					name = nextPrimary.getName();
					parentNamespace = nextPrimary.getParentNamespace();
					source = nextPrimary.getSource();
					refManager.symbolRemoved(nextPrimary);
					nextPrimary.delete();
				}
				try {
					f.getSymbol().setNameAndNamespace(name, parentNamespace, source);
					return true;
				}
				catch (Exception e) {
					return false;
				}
			}
			//refManager.symbolRemoved(sym);
			return sym.delete();
		}
		finally {
			lock.release();
		}
	}

	private Symbol findFirstNonPrimarySymbol(Address address) {
		SymbolIterator it = getSymbolsAsIterator(address);
		for (Symbol symbol : it) {
			if (!symbol.isPrimary()) {
				return symbol; // return the first non-primary symbol we find
			}
		}
		return null;
	}

	void removeChildren(SymbolDB sym) {
		ArrayList<Symbol> list = new ArrayList<>(20);
		SymbolIterator symIt = getChildren(sym);
		while (symIt.hasNext()) {
			list.add(symIt.next());
		}
		Iterator<Symbol> it = list.iterator();
		while (it.hasNext()) {
			Symbol s = it.next();
			s.delete();
		}
	}

	/**
	 * Removes the symbol directly
	 * @param sym the symbol to remove.
	 * @return true if the symbol was removed, false otherwise.
	 */
	boolean doRemoveSymbol(SymbolDB sym) {
		lock.acquire();
		try {
			if (sym == null) {
				return false;
			}
			if (sym.getID() > 0) {
				removeChildren(sym);
			}
			long id = sym.getKey();
			long parentId = sym.getParentID();
			SymbolType symType = sym.getSymbolType();
			try {
				Address address = sym.getAddress();
//				if (address.isVariableAddress()) {
//					variableStorageMgr.deleteVariableStorage(address);
//				}
				String name = sym.getName();
				boolean primary = sym.isPrimary();

				// Remove associated references
				refManager.symbolRemoved(sym);

				adapter.removeSymbol(id);
				cache.delete(id);
				//sym.setInvalid(); // already invalidated by removeObj

				// if any symbols still exist here, then
				// make one of these remaining symbols 'primary'
				//
				if (primary && address.isMemoryAddress()) {
					Symbol[] remainingSyms = getSymbols(address);
					if (remainingSyms.length > 0 &&
						remainingSyms[0].getSource() != SourceType.DEFAULT) {
						remainingSyms[remainingSyms.length - 1].setPrimary();
					}
				}
				symbolRemoved(sym, address, name, id, parentId, symType);
				return true;
			}
			catch (IOException e) {
				program.dbError(e);
			}
		}
		finally {
			lock.release();
		}
		return false;
	}

	@Override
	public boolean hasSymbol(Address addr) {
		try {
			if (adapter.hasSymbol(addr)) {
				return true;
			}
			return (addr.isMemoryAddress() && refManager.hasReferencesTo(addr));
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return false;
	}

	@Override
	public Symbol getSymbol(long symbolID) {
		if (symbolID == Namespace.GLOBAL_NAMESPACE_ID) {
			return program.getGlobalNamespace().getSymbol();
		}
		lock.acquire();
		try {
			SymbolDB s = cache.get(symbolID);
			if (s != null) {
				return s;
			}
			try {
				DBRecord record = adapter.getSymbolRecord(symbolID);
				if (record != null) {
					return createCachedSymbol(record);
				}

			}
			catch (IOException e) {
				program.dbError(e);
			}
			try {
				Address a = getDynamicAddress(symbolID);
				if (a.getAddressSpace().isMemorySpace()) {
					s = new CodeSymbol(this, cache, a, symbolID);
					return s;
				}
			}
			catch (Exception e) {
				// handled below
			}
			return null;
		}
		finally {
			lock.release();
		}
	}

	private SymbolDB getDynamicSymbol(Address addr) {
		lock.acquire();
		try {
			long symbolID = getDynamicSymbolID(addr);
			SymbolDB s = cache.get(symbolID);
			if (s != null) {
				return s;
			}
			s = new CodeSymbol(this, cache, addr, symbolID);
			return s;
		}
		finally {
			lock.release();
		}
	}

	boolean hasDynamicSymbol(Address address) {
		if (!address.isMemoryAddress()) {
			return false;
		}
		try {
			if (adapter.getSymbolIDs(address).length > 0) {
				return false;
			}
			return refManager.hasReferencesTo(address);
		}
		catch (IOException e) {
			dbError(e);
		}
		return false;
	}

	@Override
	public SymbolIterator getSymbolsAsIterator(Address addr) {
		lock.acquire();
		try {
			RecordIterator iterator = adapter.getSymbols(addr, addr, true);
			return new SymbolRecordIterator(iterator, true, true);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return new SymbolRecordIterator(new EmptyRecordIterator(), true, true);
	}

	@Override
	public Symbol[] getSymbols(Address addr) {
		lock.acquire();
		try {
			Field[] symbolIDs = adapter.getSymbolIDs(addr);
			if (symbolIDs.length == 0) {
				if (addr.isMemoryAddress() && refManager.hasReferencesTo(addr)) {
					Symbol[] symbols = new SymbolDB[1];
					symbols[0] = getDynamicSymbol(addr);
					return symbols;
				}
				return NO_SYMBOLS;
			}
			int primarySymbolIndex = 0;
			Symbol[] symbols = new Symbol[symbolIDs.length];
			for (int i = 0; i < symbols.length; i++) {
				symbols[i] = getSymbol(symbolIDs[i].getLongValue());
				// NOTE: Primary symbol concept only applies to in memory symbols
				if (addr.isMemoryAddress() && i != 0 && symbols[i].isPrimary()) {
					primarySymbolIndex = i;
				}
			}
			if (primarySymbolIndex != 0) {
				// ensure that primary symbol is placed in slot 0
				Symbol s = symbols[primarySymbolIndex];
				symbols[primarySymbolIndex] = symbols[0];
				symbols[0] = s;
			}
			return symbols;
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}

		return NO_SYMBOLS;
	}

	@Override
	public Symbol[] getUserSymbols(Address addr) {
		lock.acquire();
		try {
			Field[] symbolIDs = adapter.getSymbolIDs(addr);
			if (symbolIDs.length == 0) {
				return NO_SYMBOLS;
			}

			Symbol[] symbols = new Symbol[symbolIDs.length];
			for (int i = 0; i < symbols.length; i++) {
				symbols[i] = getSymbol(symbolIDs[i].getLongValue());
			}
			return symbols;
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return NO_SYMBOLS;
	}

	@Override
	public Symbol getSymbol(String name, Address address, Namespace namespace) {
		if (namespace == null) {
			namespace = program.getGlobalNamespace();
		}

		long namespaceId = namespace.getID();

		lock.acquire();
		try {
			DBRecord record = adapter.getSymbolRecord(address, name, namespaceId);
			if (record != null) {
				return getSymbol(record);
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}

		// check for default external symbol
		if (namespace.isExternal() && SymbolUtilities.isPossibleDefaultExternalName(name)) {
			return searchNamespaceForSymbol(namespace, name, address);
		}

		// also check for possible default parameter or local variable symbol
		if (namespace instanceof Function &&
			SymbolUtilities.isPossibleDefaultLocalOrParamName(name)) {
			return searchNamespaceForSymbol(namespace, name, address);
		}

		// check if name is a default name
		Symbol symbol = getSymbolForDynamicName(name);
		if (symbol != null && address.equals(symbol.getAddress()) &&
			namespace.equals(symbol.getParentNamespace())) {
			return symbol;
		}
		return null;
	}

	private Symbol searchNamespaceForSymbol(Namespace namespace, String name, Address address) {
		for (Symbol symbol : getSymbols(namespace)) {// NOTE: thunks do not exist in external space
			if (address.equals(symbol.getAddress()) && name.equals(symbol.getName())) {
				return symbol;
			}
		}
		return null;
	}

	private static boolean isDefaultThunk(Symbol sym) {
		return sym.getSource() == SourceType.DEFAULT && (sym instanceof FunctionSymbol) &&
			((FunctionSymbol) sym).isThunk();
	}

	@Override
	public Symbol getGlobalSymbol(String name, Address addr) {
		return getSymbol(name, addr, program.getGlobalNamespace());
	}

	@Override
	public List<Symbol> getGlobalSymbols(String name) {
		return getSymbols(name, namespaceMgr.getGlobalNamespace());
	}

	@Override
	public Symbol getLibrarySymbol(String name) {
		lock.acquire();
		try {
			for (Symbol s : getSymbols(name)) {
				if (s.getSymbolType() == SymbolType.LIBRARY) {
					return s;
				}
			}
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public List<Symbol> getSymbols(String name, Namespace namespace) {
		if (namespace == null) {
			namespace = namespaceMgr.getGlobalNamespace();
		}

		// if name is possible default parameter or local variable name, must do brute force search
		if (namespace instanceof Function &&
			SymbolUtilities.isPossibleDefaultLocalOrParamName(name)) {
			return searchNamespaceForSymbols(name, namespace);
		}

		// if the name is a possible default external name, do brute force search
		if (namespace.isExternal() && SymbolUtilities.isPossibleDefaultExternalName(name)) {
			return searchNamespaceForSymbols(name, namespace);
		}

		List<Symbol> list = new ArrayList<>();
		lock.acquire();
		try {
			RecordIterator it = adapter.getSymbolsByNameAndNamespace(name, namespace.getID());
			while (it.hasNext()) {
				list.add(getSymbol(it.next()));
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}

		// also check if the given name could be a default symbol
		Symbol symbol = getSymbolForDynamicName(name);
		if (symbol != null && symbol.getParentNamespace().equals(namespace)) {
			list.add(symbol);
		}

		return list;
	}

	private List<Symbol> searchNamespaceForSymbols(String name, Namespace namespace) {
		List<Symbol> list = new ArrayList<>();
		for (Symbol symbol : getSymbols(namespace)) {
			if (name.equals(symbol.getName())) {
				list.add(symbol);
			}
		}
		return list;
	}

	private Symbol searchNamespaceForFirstSymbol(String name, Namespace namespace,
			Predicate<Symbol> test) {
		for (Symbol symbol : getSymbols(namespace)) {
			if (name.equals(symbol.getName()) && test.test(symbol)) {
				return symbol;
			}
		}
		return null;
	}

	private Symbol getSymbolForDynamicName(String name) {
		Address address = SymbolUtilities.parseDynamicName(addrMap.getAddressFactory(), name);
		if (address != null) {
			Symbol primarySymbol = getPrimarySymbol(address);
			if (primarySymbol != null && primarySymbol.getSource() == SourceType.DEFAULT &&
				name.equals(primarySymbol.getName())) {
				return primarySymbol;
			}
		}
		return null;
	}

	// note: this could be public; adding it may be confusing due to the potential for having
	//       multiple symbols and not knowing when to call which method.
	private Symbol getFirstSymbol(String name, Namespace namespace, Predicate<Symbol> test) {
		if (namespace == null) {
			namespace = namespaceMgr.getGlobalNamespace();
		}

		// if name is possible default parameter or local variable name, must do brute force search
		if (namespace instanceof Function &&
			SymbolUtilities.isPossibleDefaultLocalOrParamName(name)) {
			return searchNamespaceForFirstSymbol(name, namespace, test);
		}

		// if the name is a possible default external name, do brute force search
		if (namespace.isExternal() && SymbolUtilities.isPossibleDefaultExternalName(name)) {
			return searchNamespaceForFirstSymbol(name, namespace, test);
		}

		lock.acquire();
		try {
			RecordIterator it = adapter.getSymbolsByNameAndNamespace(name, namespace.getID());
			while (it.hasNext()) {
				SymbolDB symbol = getSymbol(it.next());
				if (test.test(symbol)) {
					return symbol;
				}
			}
			// didn't find one in the database, see if it is a default dynamic name
			Symbol symbol = getSymbolForDynamicName(name);
			if (symbol != null && symbol.getParentNamespace().equals(namespace) &&
				test.test(symbol)) {
				return symbol;
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public Namespace getNamespace(String name, Namespace namespace) {
		List<Symbol> symbols = getSymbols(name, namespace);
		for (Symbol symbol : symbols) {
			SymbolType symbolType = symbol.getSymbolType();
			if (symbolType.isNamespace() && !symbolType.allowsDuplicates()) {
				return (Namespace) symbol.getObject();
			}
		}
		return null;
	}

	@Override
	public SymbolIterator getSymbols(Namespace namespace) {
		return getSymbols(namespace.getID());
	}

	@Override
	public SymbolIterator getSymbols(long namespaceID) {
		try {
			RecordIterator it = adapter.getSymbolsByNamespace(namespaceID);
			return new SymbolRecordIterator(it, false, true);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	@Override
	public SymbolIterator getSymbols(String name) {
		lock.acquire();
		try {
			SymbolIterator symIter = new SymbolNameRecordIterator(name);
			if (!symIter.hasNext()) {
				Symbol symbol = getSymbolForDynamicName(name);
				return new SingleSymbolIterator(symbol); // this handles a null symbol
			}
			return symIter;
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public Symbol getPrimarySymbol(Address addr) {
		if (!addr.isMemoryAddress() && !addr.isExternalAddress()) {
			return null;
		}
		if (addr.isExternalAddress()) {
			Symbol[] symbols = getSymbols(addr);
			return symbols.length > 0 ? symbols[0] : null;
		}

		lock.acquire();
		try {
			DBRecord record = adapter.getPrimarySymbol(addr);
			if (record != null) {
				return getSymbol(record);
			}
			if (addr.isMemoryAddress() && refManager.hasReferencesTo(addr)) {
				return getDynamicSymbol(addr);
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public Symbol getSymbol(Reference ref) {
		if (ref == null) {
			return null;
		}
		long symId = ref.getSymbolID();
		if (symId >= 0) {
			return getSymbol(symId);
		}
		if (!ref.isExternalReference()) {
			// We check for variables first just in case ref refers to a memory parameter
			Variable var = refManager.getReferencedVariable(ref);
			if (var != null) {
				return var.getSymbol();
			}
		}
		return getPrimarySymbol(ref.getToAddress());
	}

	/**
	 * Returns the maximum symbol address within the specified address space.
	 * @param space address space
	 * @return maximum symbol address within space or null if none are found.
	 */
	public Address getMaxSymbolAddress(AddressSpace space) {
		try {
			return adapter.getMaxSymbolAddress(space);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	/**
	 * Returns the next available external symbol address
	 * @return the address
	 */
	public Address getNextExternalSymbolAddress() {
		int extID = 1;
		Address maxAddr = getMaxSymbolAddress(AddressSpace.EXTERNAL_SPACE);
		if (maxAddr != null) {
			extID = (int) maxAddr.getOffset() + 1;
		}
		return AddressSpace.EXTERNAL_SPACE.getAddress(extID);
	}

	@Override
	public SymbolIterator getPrimarySymbolIterator(Address startAddr, boolean forward) {
		return getPrimarySymbolIterator(
			program.getAddressFactory().getAddressSet(startAddr, program.getMaxAddress()), forward);
	}

	@Override
	public SymbolIterator getPrimarySymbolIterator(AddressSetView set, boolean forward) {
		if (set.isEmpty()) {
			return SymbolIterator.EMPTY_ITERATOR;
		}
		try {
			RecordIterator recordIterator = adapter.getPrimarySymbols(set, forward);
			return new SymbolRecordIterator(recordIterator, true, forward);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return new SymbolRecordIterator(new EmptyRecordIterator(), true, forward);
	}

	@Override
	public SymbolIterator getSymbols(AddressSetView set, SymbolType type, boolean forward) {
		if (set.isEmpty()) {
			return SymbolIterator.EMPTY_ITERATOR;
		}
		Query query =
			new FieldMatchQuery(SymbolDatabaseAdapter.SYMBOL_TYPE_COL, new ByteField(type.getID()));
		return new AddressSetFilteredSymbolIterator(this, set, query, forward);
	}

	@Override
	public SymbolIterator getPrimarySymbolIterator(boolean forward) {
		return getPrimarySymbolIterator(program.getMemory(), forward);
	}

	@Override
	public SymbolIterator getSymbolIterator(Address startAddr, boolean forward) {
		RecordIterator it;
		try {
			it = adapter.getSymbolsByAddress(startAddr, forward);
		}
		catch (IOException e) {
			program.dbError(e);
			it = new EmptyRecordIterator();
		}
		return new SymbolRecordIterator(it, true, forward);
	}

	@Override
	public SymbolIterator getSymbolIterator() {
		return getSymbolIterator(true);
	}

	@Override
	public SymbolIterator getAllSymbols(boolean includeDynamicSymbols) {
		if (includeDynamicSymbols) {
			return new IncludeDynamicSymbolIterator();
		}
		return getSymbolIterator(true);
	}

	@Override
	public SymbolIterator getSymbolIterator(boolean forward) {
		try {
			RecordIterator it = adapter.getSymbolsByAddress(forward);
			return new SymbolRecordIterator(it, true, forward);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	@Override
	public SymbolIterator getSymbolIterator(String searchStr, boolean caseSensitive) {
		try {
			RecordIterator iter = adapter.getSymbols();
			SymbolIterator symbolIterator = new SymbolRecordIterator(iter, false, true);
			return new SymbolQueryIterator(symbolIterator, searchStr, caseSensitive);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	@Override
	public void addExternalEntryPoint(Address addr) {
		refManager.addExternalEntryPointRef(addr);
	}

	@Override
	public AddressIterator getExternalEntryPointIterator() {
		return refManager.getExternalEntryIterator();
	}

	@Override
	public boolean isExternalEntryPoint(Address addr) {
		return refManager.isExternalEntryPoint(addr);
	}

	@Override
	public void removeExternalEntryPoint(Address addr) {
		refManager.removeExternalEntryPoint(addr);
	}

	@Override
	public boolean hasLabelHistory(Address addr) {
		try {
			RecordIterator iter = historyAdapter.getRecordsByAddress(addrMap.getKey(addr, false));
			return iter.hasNext();
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return false;
	}

	@Override
	public Iterator<LabelHistory> getLabelHistory() {
		try {
			return new LabelHistoryIterator(historyAdapter.getAllRecords());
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return new LabelHistoryIterator(new EmptyRecordIterator());
	}

	@Override
	public LabelHistory[] getLabelHistory(Address addr) {
		ArrayList<LabelHistory> list = new ArrayList<>();
		try {
			RecordIterator iter = historyAdapter.getRecordsByAddress(addrMap.getKey(addr, false));
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				list.add(new LabelHistory(
					addrMap.decodeAddress(rec.getLongValue(LabelHistoryAdapter.HISTORY_ADDR_COL)),
					rec.getString(LabelHistoryAdapter.HISTORY_USER_COL),
					rec.getByteValue(LabelHistoryAdapter.HISTORY_ACTION_COL),
					rec.getString(LabelHistoryAdapter.HISTORY_LABEL_COL),
					new Date(rec.getLongValue(LabelHistoryAdapter.HISTORY_DATE_COL))));
			}
			LabelHistory[] h = new LabelHistory[list.size()];
			return list.toArray(h);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return new LabelHistory[0];
	}

	@Override
	public void invalidateCache(boolean all) {
		variableStorageMgr.invalidateCache(all);
		lock.acquire();
		try {
			cache.invalidate();
			dynamicSymbolAddressMap.reconcile();
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Move symbol.  Only symbol address is changed.
	 * References must be moved separately.
	 * @param oldAddr the old symbol address
	 * @param newAddr the new symbol address
	 */
	public void moveSymbolsAt(Address oldAddr, Address newAddr) {
		lock.acquire();
		try {
			long oldAddrKey = addrMap.getKey(oldAddr, false);
			if (oldAddrKey != AddressMap.INVALID_ADDRESS_KEY) {
				invalidateCache(true);
				adapter.moveAddress(oldAddr, newAddr);
				historyAdapter.moveAddress(oldAddrKey, addrMap.getKey(newAddr, true));
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public long getDynamicSymbolID(Address addr) {
		// Unique dynamic symbol ID produced from a dynamic symbol address map which has a
		// high-order bit set to avoid potential conflict with stored symbol ID's which are
		// assigned starting at 0.
		return dynamicSymbolAddressMap.getKey(addr);
	}

	Address getDynamicAddress(long dynamicSymbolID) {
		return dynamicSymbolAddressMap.decodeAddress(dynamicSymbolID);
	}

	ProgramDB getProgram() {
		return program;
	}

	DataType getDataType(long dataTypeID) {
		return program.getDataTypeManager().getDataType(dataTypeID);
	}

	AddressMap getAddressMap() {
		return addrMap;
	}

	CodeManager getCodeManager() {
		return program.getCodeManager();
	}

	ReferenceDBManager getReferenceManager() {
		return refManager;
	}

	FunctionManagerDB getFunctionManager() {
		return (FunctionManagerDB) program.getFunctionManager();
	}

	ExternalManagerDB getExternalManager() {
		return (ExternalManagerDB) program.getExternalManager();
	}

	/**
	 * Called by the NamespaceManager when a namespace is removed; remove all symbols that have the
	 * given namespace ID.
	 * @param namespaceID ID of namespace being removed
	 */
	public void namespaceRemoved(long namespaceID) {
		lock.acquire();
		try {
			try {
				ArrayList<SymbolDB> symbols = new ArrayList<>();
				RecordIterator iter = adapter.getSymbolsByNamespace(namespaceID);
				while (iter.hasNext()) {
					DBRecord rec = iter.next();
					symbols.add(getSymbol(rec));
				}
				Iterator<SymbolDB> it = symbols.iterator();
				while (it.hasNext()) {
					SymbolDB s = it.next();
					s.delete();
				}
			}
			catch (IOException e) {
				dbError(e);
			}
		}
		finally {
			lock.release();
		}
	}

	void symbolRenamed(Symbol symbol, String oldName) {
		Address addr = symbol.getAddress();
		String newName = symbol.getName();
		if (!symbol.isDynamic()) {
			createLabelHistoryRecord(addr, oldName, newName, LabelHistory.RENAME);
		}

		program.symbolChanged(symbol, ChangeManager.DOCR_SYMBOL_RENAMED, addr, symbol, oldName,
			newName);
	}

	void symbolNamespaceChanged(Symbol symbol, Namespace oldParentNamespace) {
		program.symbolChanged(symbol, ChangeManager.DOCR_SYMBOL_SCOPE_CHANGED, symbol.getAddress(),
			symbol, oldParentNamespace, symbol.getParentNamespace());
	}

	void primarySymbolSet(Symbol symbol, Symbol oldPrimarySymbol) {
		// fire event: old Value = symbol address, new value = reference address
		program.symbolChanged(symbol, ChangeManager.DOCR_SYMBOL_SET_AS_PRIMARY, symbol.getAddress(),
			null, oldPrimarySymbol, symbol);
	}

	void symbolSourceChanged(Symbol symbol) {
		program.symbolChanged(symbol, ChangeManager.DOCR_SYMBOL_SOURCE_CHANGED, symbol.getAddress(),
			symbol, null, null);
	}

	void symbolAnchoredFlagChanged(Symbol symbol) {
		program.symbolChanged(symbol, ChangeManager.DOCR_SYMBOL_ANCHORED_FLAG_CHANGED,
			symbol.getAddress(), symbol, null, null);
	}

	void symbolDataChanged(Symbol symbol) {
		program.symbolChanged(symbol, ChangeManager.DOCR_SYMBOL_DATA_CHANGED, symbol.getAddress(),
			symbol, null, null);
	}

	SymbolDatabaseAdapter getDatabaseAdapter() {
		return adapter;
	}

	DBRecord getSymbolRecord(long symbolID) {
		try {
			return adapter.getSymbolRecord(symbolID);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	void dbError(IOException e) {
		program.dbError(e);
	}

	void validateSource(String name, Address address, SymbolType symbolType, SourceType source) {
		if (!symbolType.isValidSourceType(source, address)) {
			String msg = "Can't set source to " + source + " for symbol '" + name +
				"' since it is a " + symbolType + " symbol type.";
			throw new IllegalArgumentException(msg);
		}
	}

	private void symbolAdded(Symbol symbol) {
		Address addr = symbol.getAddress();
		// create a label history record
		if (!symbol.isDynamic()) {
			createLabelHistoryRecord(addr, null, symbol.getName(), LabelHistory.ADD);
		}

		refManager.symbolAdded(symbol);

		// fire event
		program.symbolAdded(symbol, ChangeManager.DOCR_SYMBOL_ADDED, addr, null, symbol);
	}

	private void symbolRemoved(Symbol symbol, Address addr, String name, long symbolID,
			long parentId, SymbolType symType) {

		// create a label history record
		if (symType == SymbolType.LABEL || symType == SymbolType.FUNCTION) {
			createLabelHistoryRecord(addr, null, name, LabelHistory.REMOVE);
		}

		// fire event
		program.symbolChanged(symbol, ChangeManager.DOCR_SYMBOL_REMOVED, addr, symbol, name,
			symbolID);
	}

	void externalEntryPointRemoved(Address addr) {
		program.setChanged(ChangeManager.DOCR_EXTERNAL_ENTRY_POINT_REMOVED, addr, addr, null, null);
	}

	private void createLabelHistoryRecord(Address address, String oldName, String name,
			byte actionID) {

		long addr = addrMap.getKey(address, true);
		String labelStr = name;
		if (actionID == LabelHistory.RENAME) {
			labelStr = oldName + " to " + name;
		}

		try {
			historyAdapter.createRecord(addr, actionID, labelStr);
		}
		catch (IOException e) {
			program.dbError(e);
		}
	}

	private SymbolDB createCachedSymbol(DBRecord record) {
		long addr = record.getLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL);
		byte typeID = record.getByteValue(SymbolDatabaseAdapter.SYMBOL_TYPE_COL);
		SymbolType type = SymbolType.getSymbolType(typeID);
		SymbolDB s = makeSymbol(addrMap.decodeAddress(addr), record, type);
		return s;
	}

	SymbolDB getSymbol(DBRecord record) {
		lock.acquire();
		try {
			SymbolDB s = cache.get(record);
			if (s != null) {
				return s;
			}
			return createCachedSymbol(record);
		}
		finally {
			lock.release();
		}
	}

	private class SingleSymbolIterator implements SymbolIterator {

		Symbol sym;

		SingleSymbolIterator(Symbol sym) {
			this.sym = sym;
		}

		@Override
		public boolean hasNext() {
			return sym != null;
		}

		@Override
		public Symbol next() {
			Symbol s = sym;
			sym = null;
			return s;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public Iterator<Symbol> iterator() {
			return this;
		}
	}

	private class IncludeDynamicSymbolIterator implements SymbolIterator {
		private SymbolIterator symbolIt;

		private AddressIterator addrIt;

		private Symbol nextDynamicSymbol;

		private Symbol nextRealSymbol;

		private Symbol nextSymbol;

		IncludeDynamicSymbolIterator() {
			symbolIt = getSymbolIterator(true);
			addrIt = refManager.getReferenceDestinationIterator(
				program.getAddressFactory().getAddressSet(), true);
		}

		@Override
		public boolean hasNext() {
			if (nextSymbol == null) {
				findNext();
			}
			return nextSymbol != null;
		}

		@Override
		public Symbol next() {
			if (hasNext()) {
				Symbol s = nextSymbol;
				nextSymbol = null;
				return s;
			}
			return null;
		}

		private void findNext() {
			if (nextRealSymbol == null) {
				findNextRealSymbol();
			}
			if (nextDynamicSymbol == null) {
				findNextDynamicSymbol();
			}
			if (compareSymbols(nextRealSymbol, nextDynamicSymbol) < 0) {
				nextSymbol = nextRealSymbol;
				nextRealSymbol = null;
			}
			else {
				nextSymbol = nextDynamicSymbol;
				nextDynamicSymbol = null;
			}
		}

		private int compareSymbols(Symbol sym1, Symbol sym2) {
			if (sym1 == null) {
				return 1;
			}
			else if (sym2 == null) {
				return -1;
			}
			return sym1.getAddress().compareTo(sym2.getAddress());
		}

		private void findNextRealSymbol() {
			nextRealSymbol = symbolIt.next();
		}

		private void findNextDynamicSymbol() {
			while (addrIt.hasNext()) {
				Symbol symbol = getPrimarySymbol(addrIt.next());
				if (symbol != null && symbol.isDynamic()) {
					nextDynamicSymbol = symbol;
					return;
				}
			}
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public Iterator<Symbol> iterator() {
			return this;
		}
	}

	private class SymbolRecordIterator implements SymbolIterator {
		private Symbol nextSymbol;

		private final RecordIterator it;
		private final boolean includeDefaultThunks;
		private final boolean forward;

		SymbolRecordIterator(RecordIterator it, boolean includeDefaultThunks, boolean forward) {
			this.it = it;
			this.includeDefaultThunks = includeDefaultThunks;
			this.forward = forward;
		}

		@Override
		public boolean hasNext() {
			if (nextSymbol != null) {
				return true;
			}

			try {
				lock.acquire();
				while (nextSymbol == null && (forward ? it.hasNext() : it.hasPrevious())) {
					DBRecord rec = forward ? it.next() : it.previous();
					Symbol sym = getSymbol(rec);
					if (includeDefaultThunks || !isDefaultThunk(sym)) {
						nextSymbol = sym;
					}
				}
				return nextSymbol != null;
			}
			catch (IOException e) {
				program.dbError(e);
			}
			finally {
				lock.release();
			}
			return false;
		}

		@Override
		public Symbol next() {
			if (hasNext()) {
				Symbol returnedSymbol = nextSymbol;
				nextSymbol = null;
				return returnedSymbol;
			}
			return null;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public Iterator<Symbol> iterator() {
			return this;
		}
	}

	private class SymbolQueryIterator implements SymbolIterator {
		private SymbolIterator it;
		private Symbol nextMatch;
		private Pattern pattern;

		SymbolQueryIterator(SymbolIterator it, String query, boolean caseSensitive) {
			this.it = it;

			pattern = UserSearchUtils.createSearchPattern(query, caseSensitive);
		}

		@Override
		public boolean hasNext() {
			if (nextMatch == null) {
				findNextMatch();
			}
			return nextMatch != null;
		}

		@Override
		public Symbol next() {
			if (hasNext()) {
				Symbol next = nextMatch;
				nextMatch = null;
				return next;
			}
			return null;
		}

		private void findNextMatch() {
			while (it.hasNext()) {
				Symbol s = it.next();
				Matcher matcher = pattern.matcher(s.getName());
				if (matcher.matches()) {
					nextMatch = s;
					return;
				}
			}
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public Iterator<Symbol> iterator() {
			return this;
		}
	}

	private class SymbolNameRecordIterator implements SymbolIterator {
		private RecordIterator it;

		SymbolNameRecordIterator(String name) throws IOException {
			this.it = adapter.getSymbolsByName(name);
		}

		@Override
		public boolean hasNext() {
			try {
				return it.hasNext();
			}
			catch (IOException e) {
				dbError(e);
			}
			return false;
		}

		@Override
		public Symbol next() {
			if (hasNext()) {
				try {
					return getSymbol(it.next());
				}
				catch (IOException e) {
					dbError(e);
				}
			}
			return null;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public Iterator<Symbol> iterator() {
			return this;
		}
	}

	private class ExternalSymbolNameRecordIterator implements SymbolIterator {

		private RecordIterator it;
		private Symbol nextMatch;

		ExternalSymbolNameRecordIterator(String name) throws IOException {
			this.it = adapter.getSymbolsByName(name);
		}

		@Override
		public boolean hasNext() {
			if (nextMatch == null) {
				findNextMatch();
			}
			return nextMatch != null;
		}

		@Override
		public Symbol next() {
			if (hasNext()) {
				Symbol next = nextMatch;
				nextMatch = null;
				return next;
			}
			return null;
		}

		private void findNextMatch() {
			try {
				while (it.hasNext()) {
					Symbol sym = getSymbol(it.next());
					if (sym.isExternal()) {
						nextMatch = sym;
						return;
					}
				}
				nextMatch = null;
			}
			catch (IOException e) {
				dbError(e);
				nextMatch = null;
			}
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public Iterator<Symbol> iterator() {
			return this;
		}

	}

	private class LabelHistoryIterator implements Iterator<LabelHistory> {
		private RecordIterator iter;

		LabelHistoryIterator(RecordIterator iter) {
			this.iter = iter;
		}

		@Override
		public boolean hasNext() {
			try {
				return iter.hasNext();
			}
			catch (IOException e) {
				program.dbError(e);
			}
			return false;
		}

		@Override
		public LabelHistory next() {
			try {
				DBRecord rec = iter.next();
				if (rec != null) {
					return new LabelHistory(
						addrMap.decodeAddress(
							rec.getLongValue(LabelHistoryAdapter.HISTORY_ADDR_COL)),
						rec.getString(LabelHistoryAdapter.HISTORY_USER_COL),
						rec.getByteValue(LabelHistoryAdapter.HISTORY_ACTION_COL),
						rec.getString(LabelHistoryAdapter.HISTORY_LABEL_COL),
						new Date(rec.getLongValue(LabelHistoryAdapter.HISTORY_DATE_COL)));
				}
			}
			catch (IOException e) {
				program.dbError(e);
			}
			return null;

		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException("Cannot remove records through iterator!");
		}

	}

	@Override
	public Namespace getNamespace(Address addr) {
		if (addr instanceof OldGenericNamespaceAddress) {
// TODO: Should not be needed for upgrade
			throw new AssertException();
//			Symbol sym = getSymbol(((OldGenericNamespaceAddress)addr).getNamespaceID());
//			if (sym != null) {
//				return (Namespace)sym.getObject();
//			}
		}
		if (addr.isVariableAddress() || addr.isExternalAddress()) {
			Symbol sym = program.getSymbolTable().getPrimarySymbol(addr);
			if (sym != null) {
				return sym.getParentNamespace();
			}
			return null;
		}
		return namespaceMgr.getNamespaceContaining(addr);
	}

	@Override
	public Iterator<GhidraClass> getClassNamespaces() {
		return new ClassNamespaceIterator();
	}

	private class ClassNamespaceIterator implements Iterator<GhidraClass> {

		private QueryRecordIterator iter;

		ClassNamespaceIterator() {
			try {
				byte classTypeId = SymbolType.CLASS.getID();
				iter = new QueryRecordIterator(adapter.getSymbols(),
					rec -> classTypeId == rec.getByteValue(SymbolDatabaseAdapter.SYMBOL_TYPE_COL));
			}
			catch (IOException e) {
				dbError(e);
			}
		}

		@Override
		public boolean hasNext() {
			try {
				return iter.hasNext();
			}
			catch (IOException e) {
				dbError(e);
			}
			return false;
		}

		@Override
		public GhidraClass next() {
			try {
				if (iter.hasNext()) {
					Symbol s = getSymbol(iter.next());
					return (GhidraClass) s.getObject();
				}
			}
			catch (IOException e) {
				dbError(e);
			}
			return null;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}
	}

	@Override
	public SymbolIterator getDefinedSymbols() {
		RecordIterator it;
		try {
			it = adapter.getSymbols();
		}
		catch (IOException e) {
			program.dbError(e);
			it = new EmptyRecordIterator();
		}
		return new SymbolRecordIterator(it, true, true);
	}

	@Override
	public Symbol getExternalSymbol(String name) {
		lock.acquire();
		try {
			SymbolIterator it = getExternalSymbols(name);
			if (it.hasNext()) {
				return it.next();
			}
			return null;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public SymbolIterator getExternalSymbols(String name) {
		lock.acquire();
		try {
			SymbolIterator symIter = new ExternalSymbolNameRecordIterator(name);
			return symIter;
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public SymbolIterator getExternalSymbols() {
		RecordIterator it;
		try {
			it = adapter.getSymbols(AddressSpace.EXTERNAL_SPACE.getMinAddress(),
				AddressSpace.EXTERNAL_SPACE.getMaxAddress(), true);
		}
		catch (IOException e) {
			program.dbError(e);
			it = new EmptyRecordIterator();
		}

		// NOTE: thunks do not exist in external space
		return new SymbolRecordIterator(it, true, true);
	}

	Lock getLock() {
		return lock;
	}

	@Override
	public SymbolIterator getChildren(Symbol parentSymbol) {
		try {
			RecordIterator it = adapter.getSymbolsByNamespace(parentSymbol.getID());
			return new SymbolRecordIterator(it, false, true);
		}
		catch (IOException e) {
			dbError(e);
		}
		return null;
	}

	public void setLanguage(LanguageTranslator translator, TaskMonitor monitor)
			throws CancelledException {
		dynamicSymbolAddressMap = new AddressMapImpl((byte) 0x40, addrMap.getAddressFactory());
		invalidateCache(true);
		variableStorageMgr.setLanguage(translator, monitor);
	}

	public void replaceDataTypes(long oldDataTypeID, long newDataTypeID) {
		lock.acquire();
		try {
			RecordIterator it = adapter.getSymbols();
			while (it.hasNext()) {
				DBRecord rec = it.next();
				byte typeID = rec.getByteValue(SymbolDatabaseAdapter.SYMBOL_TYPE_COL);

				// Change datatype ID contained with symbol data1 for all
				// variable types and external code symbols
				if (typeID != SymbolType.PARAMETER.getID() &&
					typeID != SymbolType.LOCAL_VAR.getID() &&
					typeID != SymbolType.GLOBAL_VAR.getID()) {

					if (typeID == SymbolType.LABEL.getID()) {
						// Check for External Code Symbol
						Address addr = addrMap.decodeAddress(
							rec.getLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL));
						if (!addr.isExternalAddress()) {
							// Skip non-external code symbol
							continue;
						}
					}
					else {
						// Skip all other symbols
						continue;
					}
				}
				long id = rec.getLongValue(SymbolDatabaseAdapter.SYMBOL_DATATYPE_COL);
				if (id == oldDataTypeID) {
					rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_DATATYPE_COL, newDataTypeID);
					adapter.updateSymbolRecord(rec);
					symbolDataChanged(getSymbol(rec));
				}
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			cache.invalidate();
			lock.release();
		}
	}

	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		if (fromAddr.equals(toAddr)) {
			return;
		}
		Set<Address> primaryFixups = new HashSet<>();
		lock.acquire();
		try {
			invalidateCache(true);
			Address lastAddress = fromAddr.add(length - 1);
			AddressRange range = new AddressRangeImpl(fromAddr, lastAddress);

			// in order to handle overlapping ranges, need to iterate in the correct direction
			SymbolIterator symbolIterator =
				(fromAddr.compareTo(toAddr) > 0) ? getSymbolIterator(fromAddr, true)
						: getSymbolIterator(lastAddress, false);

			for (Symbol symbol : symbolIterator) {
				if (!range.contains(symbol.getAddress())) {
					break;
				}
				Address newAddress = toAddr.add(symbol.getAddress().subtract(fromAddr));

				// any address that has symbols added or removed may have a corrupted primary
				// (too many or non-existent)
				primaryFixups.add(symbol.getAddress());
				primaryFixups.add(newAddress);

				moveSymbolForMemoryBlockMove((SymbolDB) symbol, newAddress);
			}
			// go back and make sure there is a valid primary symbol at touched addresses
			fixupPrimarySymbols(primaryFixups);
		}
		finally {
			lock.release();
		}
	}

	// This method is specifically for moving symbols in the context of a memory block move
	// Since this is a memory block move, the destination range can not contain any functions, but
	// it may contain labels so we may have to deal with collisions. The other complication we have
	// to deal with is functions in the moved block that are currently pinned.
	private void moveSymbolForMemoryBlockMove(SymbolDB symbol, Address newAddress) {
		Address oldAddress = symbol.getAddress();

		// If the symbol is not pinned go ahead and move it. Only wrinkle is that there may
		// be a matching symbol at the destination. In that unlikely event, remove it, but preserve
		// its pinned status
		if (!symbol.isPinned()) {
			// if we conflict with a symbol at the destination, delete it (it can't be a function)
			// and retain its pinned status if it had one.
			boolean shouldPin = deleteMatchingSymbolAndCheckPinnedStatus(symbol, newAddress);
			symbol.moveLowLevel(newAddress, null, null, null, shouldPin);
			moveLabelHistory(oldAddress, newAddress);
			return;
		}

		// the other complicated case is a pinned function symbol. In this case we need to move
		// the function symbol, but create a replacement label in the pinned source location. Also,
		// if there is a primary symbol at the destination, we need to remove it and set the
		// function's symbol to that name.
		if (symbol.getSymbolType() == SymbolType.FUNCTION) {
			String originalName = symbol.getName();
			Namespace originalNamespace = symbol.getParentNamespace();
			SourceType originalSource = symbol.getSource();
			String newName = "";
			Namespace newNamespace = namespaceMgr.getGlobalNamespace();
			SourceType newSource = SourceType.DEFAULT;
			boolean newPinned = false;
			// see if there is a symbol at the destination
			Symbol destinationPrimary = getPrimarySymbol(newAddress);

			// so there is a symbol at the destination, steal its name and namespace and delete it.
			if (destinationPrimary != null) {
				newName = destinationPrimary.getName();
				newNamespace = destinationPrimary.getParentNamespace();  // use the destination's namespace
				newSource = destinationPrimary.getSource();
				newPinned = destinationPrimary.isPinned();
				destinationPrimary.delete();
			}
			try {
				// so move the symbol to the new address and update namespace, source, and pinned state
				symbol.moveLowLevel(newAddress, newName, newNamespace, newSource, newPinned);

				// create a pinned label to replace the pinned function symbol at the source.
				Symbol newSymbol =
					createLabel(oldAddress, originalName, originalNamespace, originalSource);
				newSymbol.setPinned(true);
			}
			catch (InvalidInputException e) {
				// can't happen - name was already valid
			}
		}
	}

	// Checks if there is a matching symbol at the given address and deletes it. Also returns if
	// the deleted symbol was pinned which we will preserve on the moved symbol
	private boolean deleteMatchingSymbolAndCheckPinnedStatus(SymbolDB symbol, Address address) {
		boolean isPinned = false;
		Symbol match = getSymbol(symbol.getName(), address, symbol.getParentNamespace());
		if (match != null) {
			isPinned = match.isPinned();
			match.delete();
		}
		return isPinned;
	}

	/**
	 * Checks to make sure there is a single valid primary symbol at each address
	 * @param set the set of addresses that may have to be fixed up
	 */
	private void fixupPrimarySymbols(Set<Address> set) {
		for (Address address : set) {
			Symbol[] symbols = getSymbols(address);

			// check if there is a valid consistent primary state amongst all the symbols at an address.
			if (hasValidPrimary(symbols)) {
				continue;
			}

			// otherwise, set them all to non-primary, find the best symbol to make primary and
			// make that one the primary symbol
			setAllSymbolsToNonPrimary(symbols);
			Symbol bestPrimary = findBestPrimary(symbols);
			bestPrimary.setPrimary();
		}
	}

	private void setAllSymbolsToNonPrimary(Symbol[] symbols) {
		for (Symbol symbol : symbols) {
			if (symbol instanceof CodeSymbol) {
				((CodeSymbol) symbol).setPrimary(false);
			}
		}
	}

	private Symbol findBestPrimary(Symbol[] symbols) {
		// first see if see if there is a function, if so that has to be the primary symbol
		for (Symbol symbol : symbols) {
			if (symbol.getSymbolType() == SymbolType.FUNCTION) {
				return symbol;
			}
		}

		// else just pick one. This is such a rare case, it isn't worth doing something more clever
		return symbols[0];
	}

	/**
	 * Checks if the givens symbols from the same address have exactly one primary symbol amongst them
	 * @param symbols the array of symbols at a an address
	 * @return true if there is exactly one primary symbol at the address (also true if no symbols at address)
	 */
	private boolean hasValidPrimary(Symbol[] symbols) {
		if (symbols.length == 0) {
			return true;
		}
		if (!symbols[0].isPrimary()) {
			return false;
		}
		for (int i = 1; i < symbols.length; i++) {
			if (symbols[i].isPrimary()) {
				return false;
			}
		}
		return getPrimarySymbol(symbols[0].getAddress()) == symbols[0];
	}

	@Override
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		lock.acquire();
		try {
			invalidateCache(true);
			Set<Address> notDeletedSet = adapter.deleteAddressRange(startAddr, endAddr, monitor);
			historyAdapter.deleteAddressRange(startAddr, endAddr, addrMap, notDeletedSet, monitor);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	public void imageBaseChanged(Address oldBase, Address newBase) {
		AddressSpace space = newBase.getAddressSpace();
		fixupPinnedSymbolsAfterRebase(oldBase, newBase, space.getMinAddress(),
			space.getMaxAddress());
	}

	private void fixupPinnedSymbolsAfterRebase(Address oldBase, Address base, Address minAddr,
			Address maxAddr) {

		List<SymbolDB> fixupPinnedSymbols = findPinnedSymbols(minAddr, maxAddr);

		Set<Address> primaryFixups = new HashSet<>();
		for (SymbolDB symbol : fixupPinnedSymbols) {
			Address currentAddress = symbol.getAddress();
			Address beforeBaseChangeAddress = oldBase.add(currentAddress.subtract(base));
			primaryFixups.add(currentAddress);
			primaryFixups.add(beforeBaseChangeAddress);

			// see if there is a name collision for the pinned symbol we are about to move back
			Symbol match =
				getSymbol(symbol.getName(), beforeBaseChangeAddress, symbol.getParentNamespace());

			if (symbol.getSymbolType() == SymbolType.FUNCTION) {
				fixupPinnedFunctionSymbolAfterRebase(symbol, beforeBaseChangeAddress, match);
			}
			else {
				fixupPinnedLabelSymbolAfterRebase(symbol, beforeBaseChangeAddress, match);
			}
		}
		fixupPrimarySymbols(primaryFixups);
	}

	private void fixupPinnedLabelSymbolAfterRebase(SymbolDB symbol, Address newAddress,
			Symbol match) {
		if (match != null) {
			match.setPinned(true);
			symbol.delete();
		}
		else {
			symbol.moveLowLevel(newAddress, null, null, null, true);
		}
	}

	private void fixupPinnedFunctionSymbolAfterRebase(SymbolDB symbol, Address newAddress,
			Symbol match) {
		// since we are a function, we are not moving the symbol, so we must either pin a
		// matching symbol at the destination or create a new pinned label at the destination.
		if (match != null) {
			match.setPinned(true);
		}
		else {
			try {
				Symbol newLabel =
					createLabel(newAddress, symbol.getName(), symbol.getParentNamespace(),
						symbol.getSource());
				newLabel.setPinned(true);
			}
			catch (InvalidInputException e) {
				// can't happen, we already know it is valid
			}
		}

		// unpin the function symbol since it is not moving.
		symbol.setPinned(false);

		// now, either set the function to default or find another symbol to promote.
		String newName = "";
		Namespace newNamespace = namespaceMgr.getGlobalNamespace();
		SourceType newSource = SourceType.DEFAULT;
		Symbol symbolToPromote = findSymbolToPromote(symbol.getAddress());
		if (symbolToPromote != null) {
			newName = symbolToPromote.getName();
			newNamespace = symbolToPromote.getParentNamespace();
			newSource = symbolToPromote.getSource();
			symbolToPromote.delete();
		}
		try {
			symbol.setNameAndNamespace(newName, newNamespace, newSource);
		}
		catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
			// can't happen
		}
	}

	private List<SymbolDB> findPinnedSymbols(Address minAddr, Address maxAddr) {
		List<SymbolDB> pinnedSymbols = new ArrayList<>();
		for (Symbol symbol : getSymbolIterator(minAddr, true)) {
			if (symbol.getAddress().compareTo(maxAddr) > 0) {
				break;
			}
			if (symbol.isPinned()) {
				pinnedSymbols.add((SymbolDB) symbol);
			}
		}
		return pinnedSymbols;
	}

	private Symbol findSymbolToPromote(Address address) {
		Symbol[] symbols = getSymbols(address);
		if (symbols.length > 1) {
			return symbols[1];
		}
		return null;
	}

	void moveLabelHistory(Address oldAddress, Address address) {
		try {
			historyAdapter.moveAddressRange(oldAddress, address, 1, addrMap, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			// can't happen, used dummy monitor
		}
		catch (IOException e) {
			dbError(e);
		}
	}

	/**
	 * Creates variable symbols. Note this is not a method defined in the Symbol Table interface.
	 * It is intended to be used by Ghidra program internals.
	 * @param name the name of the variable
	 * @param namespace the function that contains the variable.
	 * @param type the type of the variable (can only be PARAMETER or LOCAL_VAR)
	 * @param firstUseOffsetOrOrdinal the offset in the function where the variable is first used.
	 * @param storage the VariableStorage (stack, registers, etc.)
	 * @param source the symbol source type (user defined, analysis, etc.)
	 * @return the new VariableSymbol that was created.
	 * @throws DuplicateNameException if there is another variable in this function with that name.
	 * @throws InvalidInputException if the name contains illegal characters (space for example)
	 */
	public VariableSymbolDB createVariableSymbol(String name, Namespace namespace, SymbolType type,
			int firstUseOffsetOrOrdinal, VariableStorage storage, SourceType source)
			throws DuplicateNameException, InvalidInputException {

		if (type != SymbolType.PARAMETER && type != SymbolType.LOCAL_VAR) {
			throw new IllegalArgumentException("Invalid symbol type for variable: " + type);
		}

		if (!(namespace instanceof Function)) {
			throw new IllegalArgumentException(
				"Function must be namespace for local variable or parameter");
		}

		lock.acquire();
		try {
			source = adjustSourceTypeIfNecessary(name, type, source, storage);
			Address varAddr = variableStorageMgr.getVariableStorageAddress(storage, true);
			return (VariableSymbolDB) createSpecialSymbol(varAddr, name, namespace, type,
				null, Integer.valueOf(firstUseOffsetOrOrdinal), null, source);
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	private SourceType adjustSourceTypeIfNecessary(String name, SymbolType type, SourceType source,
			VariableStorage storage) {

		if (type == SymbolType.PARAMETER && SymbolUtilities.isDefaultParameterName(name)) {
			return SourceType.DEFAULT;
		}
		if (SymbolUtilities.isDefaultLocalName(program, name, storage)) {
			return SourceType.DEFAULT;
		}
		return source;
	}

	@Override
	public GhidraClass createClass(Namespace parent, String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		SymbolDB s =
			createSpecialSymbol(Address.NO_ADDRESS, name, parent, SymbolType.CLASS, null, null,
				null, source);
		return new GhidraClassDB(s, namespaceMgr);
	}

	@Override
	public Library createExternalLibrary(String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {

		SymbolDB s =
			createSpecialSymbol(Address.NO_ADDRESS, name, null, SymbolType.LIBRARY, null, null,
				null, source);
		return new LibraryDB(s, namespaceMgr);
	}

	@Override
	public Namespace createNameSpace(Namespace parent, String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {

		SymbolDB s =
			createSpecialSymbol(Address.NO_ADDRESS, name, parent, SymbolType.NAMESPACE, null,
				null, null, source);
		return new NamespaceDB(s, namespaceMgr);
	}

	@Override
	public GhidraClass convertNamespaceToClass(Namespace namespace) {

		if (namespace instanceof GhidraClass) {
			return (GhidraClass) namespace;
		}

		lock.acquire();
		try {

			checkIsValidNamespaceForMyProgram(namespace);

			Symbol namespaceSymbol = namespace.getSymbol();
			String name = namespaceSymbol.getName();
			SourceType originalSource = namespaceSymbol.getSource();

			// no duplicate check, since this class name will be set to that of the existing namespace
			String tempName = "_temp_" + System.nanoTime();
			SymbolDB classSymbol =
				doCreateSpecialSymbol(Address.NO_ADDRESS, tempName, namespace.getParentNamespace(),
					SymbolType.CLASS, null, null, null, originalSource,
					false /*check for duplicate */);
			GhidraClassDB classNamespace = new GhidraClassDB(classSymbol, namespaceMgr);

			// move everything from old namespace into new class namespace
			for (Symbol s : getSymbols(namespace)) {

				// no duplicate check, since these symbols all lived under the existing namespace
				((SymbolDB) s).doSetNameAndNamespace(s.getName(), classNamespace, s.getSource(),
					false /*check for duplicate */);
			}

			namespaceSymbol.delete();

			// fix name now that the old namespace is deleted
			classNamespace.setName(name, SourceType.ANALYSIS, false /*check for duplicate */);

			return classNamespace;
		}
		catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
			throw new AssertException("Unexpected exception creating class from namespace: " +
				e.getMessage(), e);
		}
		finally {
			lock.release();
		}
	}

	private void checkIsValidNamespaceForMyProgram(Namespace namespace) {

		if (namespace == null) {
			return;
		}

		if (namespace == program.getGlobalNamespace()) {
			return;
		}

		Symbol symbol = namespace.getSymbol();
		if (!(symbol instanceof SymbolDB)) {
			// unexpected namespace type; all supported types will be db objects
			throw new IllegalArgumentException(
				"Namespace is not a valid parent for symbols: " + namespace.getClass());
		}

		SymbolDB dbSymbol = (SymbolDB) symbol;
		if (program != dbSymbol.getProgram()) {
			throw new IllegalArgumentException(
				"Namespace symbol is from a different program");
		}

		// may throw a ConcurrentModificationException
		dbSymbol.checkDeleted();
	}

	@Override
	public Namespace getOrCreateNameSpace(Namespace parent, String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {

		lock.acquire();
		try {

			checkIsValidNamespaceForMyProgram(parent);

			Symbol namespaceSymbol = getFirstSymbol(name, parent, s -> {
				return s.getSymbolType() == SymbolType.NAMESPACE ||
					s.getSymbolType() == SymbolType.CLASS;
			});

			if (namespaceSymbol != null) {
				return (Namespace) namespaceSymbol.getObject();
			}

			// Note: We know there are no namespaces with the name; do we still have to check for
			//       duplicates?  Assuming yes, as another symbol type may exist with this name.
			SymbolDB s =
				doCreateSpecialSymbol(Address.NO_ADDRESS, name, parent, SymbolType.NAMESPACE, null,
					null, null, source, true /*check for duplicates*/);
			return new NamespaceDB(s, namespaceMgr);

		}
		finally {
			lock.release();
		}
	}

	/**
	 * Creates a symbol, specifying all information for the record.  This method is not on the
	 * public interface and is only intended for program API internal use.  The user of this
	 * method must carefully provided exactly the information needed depending on the type of symbol
	 * being created.
	 * @param addr the address for the symbol
	 * @param name the name of the symbol
	 * @param parent the namespace for the symbol
	 * @param symbolType the type of the symbol
	 * @param dataTypeId the id for an associated datatype or null
	 * @param variableOffset this is the ordinal for params and firstUseOffset for locals
	 * @param stringData value whose meaning depends on the symbol type.
	 * @param source the SourceType for the new symbol
	 * @return the newly created symbol
	 * @throws DuplicateNameException if the symbol type must be unique and another already has that name
	 * 	       in the given namespace.
	 * @throws InvalidInputException if the name contains any illegal characters (i.e. space)
	 */
	public SymbolDB createSpecialSymbol(Address addr, String name, Namespace parent,
			SymbolType symbolType, Long dataTypeId, Integer variableOffset, String stringData,
			SourceType source)
			throws DuplicateNameException, InvalidInputException {

		return doCreateSpecialSymbol(addr, name, parent, symbolType, stringData, dataTypeId,
			variableOffset, source, true);
	}

	private SymbolDB doCreateSpecialSymbol(Address addr, String name, Namespace parent,
			SymbolType symbolType, String stringData, Long dataTypeId, Integer variableOffset,
			SourceType source,
			boolean checkForDuplicates)
			throws DuplicateNameException, InvalidInputException {

		lock.acquire();
		try {
			parent = validateNamespace(parent, addr, symbolType);
			source = validateSource(source, name, addr, symbolType);
			name = validateName(name, source);

			if (checkForDuplicates) {
				checkDuplicateSymbolName(addr, name, parent, symbolType);
			}

			return doCreateSymbol(name, addr, parent, symbolType, stringData, dataTypeId,
				variableOffset, source, false);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Symbol createLabel(Address addr, String name, SourceType source)
			throws InvalidInputException {

		return createLabel(addr, name, null, source);
	}

	@Override
	public Symbol createLabel(Address addr, String name, Namespace namespace, SourceType source)
			throws InvalidInputException {
		return createCodeSymbol(addr, name, namespace, source, null);
	}

	/**
	 * Internal method for creating label symbols.
	 * @param addr the address for the new symbol
	 * @param name the name of the new symbol
	 * @param namespace the namespace for the new symbol
	 * @param source the SourceType of the new symbol
	 * @param stringData special use depending on the symbol type and whether or not it is external
	 * @return the new symbol
	 * @throws InvalidInputException if the name contains illegal characters (i.e. space)
	 */
	public Symbol createCodeSymbol(Address addr, String name, Namespace namespace,
			SourceType source, String stringData) throws InvalidInputException {
		lock.acquire();
		try {
			namespace = validateNamespace(namespace, addr, SymbolType.LABEL);
			source = validateSource(source, name, addr, SymbolType.LABEL);
			name = validateName(name, source);

			Symbol symbol = getSymbol(name, addr, namespace);
			if (symbol != null) {
				return symbol;
			}

			// If there is a default named function, rename it to the new symbol name
			Symbol functionSymbol = tryUpdatingDefaultFunction(addr, name, namespace, source);
			if (functionSymbol != null) {
				return functionSymbol;
			}

			// if there is a dynamic symbol, delete it and make the new symbol primary.
			Symbol primary = getPrimarySymbol(addr);
			if (primary != null && primary.isDynamic()) {
				deleteDynamicSymbol(primary);
				primary = null;
			}
			boolean makePrimary = primary == null;

			return doCreateSymbol(name, addr, namespace, SymbolType.LABEL, stringData, null, null,
				source, makePrimary);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Internal method for creating function symbols
	 * 
	 * @param addr the address for the new symbol
	 * @param name the name of the new symbol
	 * @param namespace the namespace for the new symbol
	 * @param source the SourceType of the new symbol
	 * @param stringData special use depending on the symbol type and whether or not it is external.
	 * @return the new symbol
	 * @throws InvalidInputException if the name contains illegal characters (i.e. space)
	 */
	public Symbol createFunctionSymbol(Address addr, String name, Namespace namespace,
			SourceType source, String stringData) throws InvalidInputException {

		namespace = validateNamespace(namespace, addr, SymbolType.FUNCTION);
		source = validateSource(source, name, addr, SymbolType.FUNCTION);
		name = validateName(name, source);

		// if there is already a FUNCTION symbol with that name and namespace here, just return it.
		Symbol matching = getSymbol(name, addr, namespace);
		if (matching != null && matching.getSymbolType() == SymbolType.FUNCTION) {
			return matching;
		}

		// if there is another function at the same address, throw InvalidInputException
		Symbol primary = getPrimarySymbol(addr);
		if (primary != null && primary.getSymbolType() == SymbolType.FUNCTION) {
			throw new InvalidInputException("Function already exists at: " + addr);
		}

		// See if there is a symbol we want to change into the function symbol
		Symbol symbolToPromote = findSymbolToPromote(matching, primary, source);
		if (symbolToPromote != null && !symbolToPromote.isDynamic()) {
			name = symbolToPromote.getName();
			namespace = symbolToPromote.getParentNamespace();
			source = symbolToPromote.getSource();
		}

		// If promoting a pinned symbol, we need to pin the new function symbol.
		boolean needsPinning = symbolToPromote == null ? false : symbolToPromote.isPinned();

		// delete any promoted symbol, dynamic symbol, and make sure all others are not primary
		cleanUpSymbols(addr, symbolToPromote, primary);

		Symbol symbol =
			doCreateSymbol(name, addr, namespace, SymbolType.FUNCTION, stringData, null, null,
				source, true);

		if (needsPinning) {
			symbol.setPinned(true);
		}

		return symbol;
	}

	/**
	 * Finds the appropriate symbol to promote when function is created. And by promote, we really
	 * mean find the symbol that needs to be deleted before creating the function symbol. If the
	 * found symbol is not dynamic, the function symbol will assume its name and namespace.
	 */
	private Symbol findSymbolToPromote(Symbol matching, Symbol primary, SourceType source) {
		// if the function is default, then the primary will be promoted
		if (source == SourceType.DEFAULT) {
			return primary;
		}
		// if the primary is a default, it needs to be deleted, so return it as the "promoted" symbol
		if (primary != null && primary.isDynamic()) {
			return primary;
		}
		// otherwise return a symbol that has the same name and namespce as the function (if it exists)
		return matching;
	}

	private void cleanUpSymbols(Address address, Symbol symbolToPromote, Symbol primary) {
		if (symbolToPromote != null) {
			if (symbolToPromote.isDynamic()) {
				deleteDynamicSymbol(symbolToPromote);
				primary = null;
			}
			else {
				symbolToPromote.delete();
				primary = getPrimarySymbol(address);
				if (primary != null && primary.isDynamic()) {
					deleteDynamicSymbol(primary);
					primary = null;
				}
			}
		}
		// clear the primary symbol during cleanup because a new symbol is about to be created
		// that will be the primary symbol
		if (primary != null && !primary.isDynamic()) {
			((CodeSymbol) primary).setPrimary(false);
		}
	}

	private Namespace validateNamespace(Namespace namespace, Address addr, SymbolType type)
			throws InvalidInputException {

		namespace = namespace == null ? namespaceMgr.getGlobalNamespace() : namespace;

		checkAddressAndNameSpaceValidForSymbolType(addr, namespace, type);

		return namespace;
	}

	private SymbolDB doCreateSymbol(String name, Address addr, Namespace namespace, SymbolType type,
			String stringData, Long dataTypeId, Integer variableOffset, SourceType source,
			boolean isPrimary) {

		try {
			DBRecord record =
				adapter.createSymbol(name, addr, namespace.getID(), type, stringData, dataTypeId,
					variableOffset, source, isPrimary);

			SymbolDB newSymbol = makeSymbol(addr, record, type);
			symbolAdded(newSymbol);
			return newSymbol;
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	private String validateName(String name, SourceType source)
			throws InvalidInputException {
		if (source == SourceType.DEFAULT) {
			return "";
		}
		SymbolUtilities.validateName(name);
		return name;
	}

	private SourceType validateSource(SourceType source, String name, Address addr,
			SymbolType type) {
		validateSource(name, addr, type, source);
		if (addr.isExternalAddress() && source != SourceType.DEFAULT) {
			if (StringUtils.isBlank(name) ||
				SymbolUtilities.isReservedDynamicLabelName(name, addrMap.getAddressFactory())) {
				return SourceType.DEFAULT;
			}
		}
		return source;
	}

	private void deleteDynamicSymbol(Symbol dynamic) {
		long key = ((SymbolDB) dynamic).getKey();
		Address address = dynamic.getAddress();
		String name = dynamic.getName();
		long namespaceID = dynamic.getParentNamespace().getID();
		cache.delete(key);
		symbolRemoved(dynamic, address, name, key, namespaceID, null);
	}

	/*
	 *  If there is a default named function at the address and the new symbol's parentNamespace
	 *  is either global or the same as the functions, then rename the function.
	 */
	private Symbol tryUpdatingDefaultFunction(Address addr, String name, Namespace namespace,
			SourceType source) throws InvalidInputException {

		if (!addr.isMemoryAddress()) {
			return null;
		}

		Function function = program.getFunctionManager().getFunctionAt(addr);
		if (function == null || function.getSymbol().getSource() != SourceType.DEFAULT) {
			return null;
		}

		// don't promote default functions to new code symbols if the code symbol is in a function namespace.
		if (isInFunctionNamespace(namespace)) {
			return null;
		}
		Symbol functionSym = function.getSymbol();
		try {
			functionSym.setNameAndNamespace(name, namespace, source);
		}
		catch (CircularDependencyException e) {
			throw new AssertException("Unexpected CircularDependencyException");
		}
		catch (DuplicateNameException e) {
			throw new AssertException("Unexpected DuplicateNameException");
		}
		return functionSym;
	}

	private boolean isInFunctionNamespace(Namespace namespace) {
		while (namespace != null) {
			if (namespace instanceof Function) {
				return true;
			}
			namespace = namespace.getParentNamespace();
		}
		return false;
	}

	private void checkAddressAndNameSpaceValidForSymbolType(Address addr, Namespace parentNamespace,
			SymbolType type) throws InvalidInputException {

		if (!type.isValidAddress(program, addr)) {
			throw new IllegalArgumentException(
				"Invalid address specified for new " + type + " symbol: " + addr);
		}

		boolean isExternal = isExternal(type, addr, parentNamespace);

		if (!type.isValidParent(program, parentNamespace, addr, isExternal)) {
			throw new InvalidInputException("Invalid parent namespace specified " + "for new " +
				type + " symbol: " + parentNamespace.getName(true));
		}
	}

	private boolean isExternal(SymbolType type, Address addr, Namespace parentNamespace) {
		if (type == SymbolType.LABEL || type == SymbolType.FUNCTION) {
			return addr.isExternalAddress();
		}
		return parentNamespace.isExternal();
	}

	@Override
	public Symbol getClassSymbol(String name, Namespace namespace) {
		return getSpecificSymbol(name, namespace, SymbolType.CLASS);
	}

	@Override
	public Symbol getParameterSymbol(String name, Namespace namespace) {
		return getSpecificSymbol(name, namespace, SymbolType.PARAMETER);
	}

	@Override
	public Symbol getLocalVariableSymbol(String name, Namespace namespace) {
		return getSpecificSymbol(name, namespace, SymbolType.LOCAL_VAR);
	}

	@Override
	public Symbol getNamespaceSymbol(String name, Namespace namespace) {
		return getSpecificSymbol(name, namespace, SymbolType.NAMESPACE);
	}

	@Override
	public List<Symbol> getLabelOrFunctionSymbols(String name, Namespace namespace) {
		List<Symbol> symbols = getSymbols(name, namespace);
		List<Symbol> filtered = new ArrayList<>();
		for (Symbol symbol : symbols) {
			SymbolType type = symbol.getSymbolType();
			if (type == SymbolType.FUNCTION || type == SymbolType.LABEL) {
				filtered.add(symbol);
			}
		}
		return filtered;
	}

	@Override
	public Symbol getVariableSymbol(String name, Function function) {
		return getFirstSymbol(name, function, s -> {
			SymbolType t = s.getSymbolType();
			return t == SymbolType.PARAMETER || t == SymbolType.LOCAL_VAR;
		});
	}

	private Symbol getSpecificSymbol(String name, Namespace namespace, SymbolType type) {
		return getFirstSymbol(name, namespace, s -> s.getSymbolType() == type);
	}
}
