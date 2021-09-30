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
package ghidra.program.database.external;

import java.io.IOException;
import java.util.*;

import db.*;
import ghidra.framework.store.FileSystem;
import ghidra.program.database.ManagerDB;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.external.ExternalLocationDB.ExternalData;
import ghidra.program.database.function.FunctionManagerDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Library;
import ghidra.program.model.symbol.*;
import ghidra.program.util.LanguageTranslator;
import ghidra.util.Lock;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Manages the database for external references.
 */
public class ExternalManagerDB implements ManagerDB, ExternalManager {

	private AddressMap addrMap;
	private NamespaceManager scopeMgr;
	private SymbolManager symbolMgr;
	private FunctionManagerDB functionMgr;

	private ProgramDB program;
	private Lock lock;

	private OldExtNameAdapter oldNameAdapter;
	private OldExtRefAdapter oldExtRefAdapter;

	/**
	 * Constructs a new ExternalManagerDB
	 * @param handle the open database handle
	 * @param addrMap the address map
	 * @param openMode the program open mode.
	 * @param lock the program synchronization lock
	 * @param monitor the progress monitor used when upgrading
	 * @throws CancelledException if the user cancelled while an upgrade was occurring
	 * @throws IOException if a database io error occurs.
	 * @throws VersionException if the database version does not match the expected version
	 */
	public ExternalManagerDB(DBHandle handle, AddressMap addrMap, int openMode, Lock lock,
			TaskMonitor monitor) throws CancelledException, IOException, VersionException {

		this.addrMap = addrMap;
		this.lock = lock;
		initializeOldAdapters(handle, openMode, monitor);
	}

	private void initializeOldAdapters(DBHandle handle, int openMode, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		try {
			// Try old adapters needed for upgrade
			oldNameAdapter = OldExtNameAdapter.getAdapter(handle, openMode, monitor);
			oldExtRefAdapter = OldExtRefAdapter.getAdapter(handle, openMode, monitor);
		}
		catch (VersionException ve) {
			//ignore
		}
		if (oldNameAdapter != null && oldExtRefAdapter != null && openMode != DBConstants.UPGRADE) {
			throw new VersionException(true);
		}
	}

	/**
	 * @see ghidra.program.database.ManagerDB#setProgram(ghidra.program.database.ProgramDB)
	 */
	@Override
	public void setProgram(ProgramDB program) {
		this.program = program;
		symbolMgr = (SymbolManager) program.getSymbolTable();
		functionMgr = (FunctionManagerDB) program.getFunctionManager();
		scopeMgr = program.getNamespaceManager();
	}

	/**
	 * @see ghidra.program.database.ManagerDB#programReady(int, int, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void programReady(int openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (openMode != DBConstants.UPGRADE) {
			return;
		}
		if (upgradeOldExtRefAdapter(monitor)) {
			return;
		}
	}

	private boolean upgradeOldExtRefAdapter(TaskMonitor monitor)
			throws IOException, CancelledException {
		if (oldNameAdapter == null || oldExtRefAdapter == null) {
			return false;
		}
		monitor.setMessage("Processing Old External Names...");
		monitor.initialize(oldNameAdapter.getRecordCount());
		int cnt = 0;

		Map<Long, String> nameMap = new HashMap<>();

		RecordIterator iter = oldNameAdapter.getRecords();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			DBRecord rec = iter.next();

			String name = rec.getString(OldExtNameAdapter.EXT_NAME_COL);
			try {
				addExternalName(name, rec.getString(OldExtNameAdapter.EXT_PATHNAME_COL),
					SourceType.USER_DEFINED);
				nameMap.put(rec.getKey(), name);
			}
			catch (DuplicateNameException e) {
				// ignore
			}
			catch (InvalidInputException e) {
				// ignore
			}
			monitor.setProgress(++cnt);
		}

		AddressMap oldAddrMap = addrMap.getOldAddressMap();
		ReferenceManager refMgr = program.getReferenceManager();

		monitor.setMessage("Processing Old External References...");
		monitor.initialize(oldExtRefAdapter.getRecordCount());
		cnt = 0;

		iter = oldExtRefAdapter.getRecords();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			DBRecord rec = iter.next();

			Address fromAddr =
				oldAddrMap.decodeAddress(rec.getLongValue(OldExtRefAdapter.FROM_ADDR_COL));
			int opIndex = rec.getShortValue(OldExtRefAdapter.OP_INDEX_COL);
			boolean userDefined = rec.getBooleanValue(OldExtRefAdapter.USER_DEFINED_COL);
			String name = nameMap.get(rec.getLongValue(OldExtRefAdapter.EXT_NAME_ID_COL));
			if (name == null) {
				continue; // should not happen
			}
			String label = rec.getString(OldExtRefAdapter.LABEL_COL);
			Address addr = rec.getBooleanValue(OldExtRefAdapter.EXT_ADDR_EXISTS_COL)
					? oldAddrMap.decodeAddress(rec.getLongValue(OldExtRefAdapter.EXT_TO_ADDR_COL))
					: null;

			try {
				refMgr.addExternalReference(fromAddr, name, label, addr,
					userDefined ? SourceType.USER_DEFINED : SourceType.IMPORTED, opIndex,
					RefType.DATA);
			}
			catch (DuplicateNameException e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}
			catch (InvalidInputException e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}
			monitor.setProgress(++cnt);
		}
		oldExtRefAdapter = null;
		return true;
	}

	/**
	 * @see ghidra.program.database.ManagerDB#invalidateCache(boolean)
	 */
	@Override
	public void invalidateCache(boolean all) throws IOException {
		// nothing to do here
	}

	/**
	 * @see ghidra.program.database.ManagerDB#deleteAddressRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		// Has no affect on externals
	}

	/**
	 * @see ghidra.program.database.ManagerDB#moveAddressRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address, long, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		// Has no affect on externals
	}

	@Override
	public ExternalLocation addExtLocation(String extLibraryName, String extLabel, Address extAddr,
			SourceType sourceType) throws InvalidInputException, DuplicateNameException {
		SourceType locSourceType = checkExternalLabel(extLabel, extAddr, sourceType);
		lock.acquire();
		try {
			Namespace libraryScope = getLibraryScope(extLibraryName);
			if (libraryScope == null) {
				libraryScope = addExternalName(extLibraryName, null, sourceType);
			}
			return addExtLocation(libraryScope, extLabel, extAddr, false, locSourceType, true);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public ExternalLocation addExtLocation(Namespace extParentNamespace, String extLabel,
			Address extAddr, SourceType sourceType)
			throws InvalidInputException, DuplicateNameException {
		lock.acquire();
		try {
			return addExtLocation(extParentNamespace, extLabel, extAddr, false, sourceType, true);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public ExternalLocation addExtLocation(Namespace extParentNamespace, String extLabel,
			Address extAddr, SourceType sourceType, boolean reuseExisting)
			throws InvalidInputException, DuplicateNameException {
		lock.acquire();
		try {
			return addExtLocation(extParentNamespace, extLabel, extAddr, false, sourceType,
				reuseExisting);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public ExternalLocation addExtFunction(String extLibraryName, String extLabel, Address extAddr,
			SourceType sourceType) throws InvalidInputException, DuplicateNameException {
		SourceType locSourceType = checkExternalLabel(extLabel, extAddr, sourceType);
		lock.acquire();
		try {
			Namespace libraryScope = getLibraryScope(extLibraryName);
			if (libraryScope == null) {
				libraryScope = addExternalName(extLibraryName, null,
					sourceType != SourceType.DEFAULT ? sourceType : SourceType.ANALYSIS);
			}
			return addExtLocation(libraryScope, extLabel, extAddr, true, locSourceType, true);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public ExternalLocation addExtFunction(Namespace extParentNamespace, String extLabel,
			Address extAddr, SourceType sourceType)
			throws InvalidInputException, DuplicateNameException {
		lock.acquire();
		try {
			return addExtLocation(extParentNamespace, extLabel, extAddr, true, sourceType, true);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public ExternalLocation addExtFunction(Namespace extNamespace, String extLabel, Address extAddr,
			SourceType sourceType, boolean reuseExisting)
			throws InvalidInputException, DuplicateNameException {

		lock.acquire();
		try {
			return addExtLocation(extNamespace, extLabel, extAddr, true, sourceType, reuseExisting);
		}
		finally {
			lock.release();
		}

	}

	private SourceType checkExternalLabel(String extLabel, Address extAddr, SourceType source)
			throws InvalidInputException {
		if (extLabel == null || extLabel.length() == 0) {
			extLabel = null;
		}
		if (extLabel == null && extAddr == null) {
			throw new InvalidInputException("Either an external label or address is required");
		}
		return extLabel == null ? SourceType.DEFAULT : source;
	}

	private ExternalLocation addExtLocation(Namespace extNamespace, String extLabel,
			Address extAddr, boolean isFunction, SourceType sourceType, boolean reuseExisting)
			throws InvalidInputException, DuplicateNameException {
		if (extNamespace == null) {
			extNamespace = getLibraryScope(Library.UNKNOWN);
			if (extNamespace == null) {
				extNamespace = addExternalLibraryName(Library.UNKNOWN, SourceType.ANALYSIS);
			}
		}
		else if (!extNamespace.isExternal()) {
			throw new InvalidInputException("The namespace must be an external namespace.");
		}
		sourceType = checkExternalLabel(extLabel, extAddr, sourceType);
		if (extAddr != null && !extAddr.isLoadedMemoryAddress()) {
			throw new InvalidInputException("Invalid memory address");
		}
		lock.acquire();
		try {
			if (sourceType == SourceType.DEFAULT) {
				extLabel = null;
			}
			ExternalLocationDB extLoc =
				(ExternalLocationDB) getExtLocation(extNamespace, extLabel, extAddr, reuseExisting);

			if (extLoc != null) {
				// if there is already a location with the address, then we must use it
				if (extAddr != null || reuseExisting) {
					if (extLabel != null && !extLabel.equals(extLoc.getLabel())) {
						extLoc.setLabel(extLabel, sourceType);
					}
					if (isFunction) {
						// transform to a function if needed
						extLoc = (ExternalLocationDB) createFunction(extLoc).getExternalLocation();
					}
					return extLoc;
				}
			}
			// ok can't or don't want to reuse an existing one, so make a new one.
			SymbolDB s;
			Address externalSpaceAddress = symbolMgr.getNextExternalSymbolAddress();
			String extMemAddrString = (extAddr != null) ? extAddr.toString() : null;
			if (isFunction) {
				Function function = functionMgr.createExternalFunction(externalSpaceAddress,
					extLabel, extNamespace, extMemAddrString, sourceType);
				s = (SymbolDB) function.getSymbol();
			}
			else {
				s = (SymbolDB) symbolMgr.createCodeSymbol(externalSpaceAddress, extLabel,
					extNamespace, sourceType, extMemAddrString);
			}
			return new ExternalLocationDB(this, s);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Get the external location which best matches the specified parameters.
	 * Preference is given to extLabel over extAddr
	 * @param libScope, the library namespace containing this external location.
	 * @param extLabel the name of the external location. Can be null.
	 * @param extAddr the address of function in the external program.  Can be null
	 * @return the best matching ExternalLocation or null.
	 * @throws InvalidInputException if the extLabel name contains illegal characters (i.e. space)
	 */
	private ExternalLocation getExtLocation(Namespace library, String extLabel, Address extAddr,
			boolean reuseExisting) throws InvalidInputException {

		if (extLabel != null && (extLabel.length() == 0 ||
			SymbolUtilities.isReservedExternalDefaultName(extLabel, addrMap.getAddressFactory()))) {
			extLabel = null; // force use of address
		}

		ExternalLocation match =
			findMatchingLocationByName(library, extLabel, extAddr, reuseExisting);
		if (match != null) {
			return match;
		}

		// So now get all the externalLocations for a library and search them
		List<ExternalLocation> locations = getExternalLocations(library);

		if (extLabel == null) {
			return findMatchingLocationByAddress(locations, extAddr, reuseExisting);
		}

		return findMatchingLocationByOriginalImportName(locations, extLabel, extAddr);
	}

	// Find the location whose original imported name matches the given extLabel name.
	private ExternalLocation findMatchingLocationByOriginalImportName(
			List<ExternalLocation> locations, String extLabel, Address extAddr) {

		// this only makes sense if we have label and no address.  If we have an address,
		// then the address must match and we would have already found it.
		if (extLabel != null && extAddr == null) {
			for (ExternalLocation externalLocation : locations) {
				if (extLabel.equals(externalLocation.getOriginalImportedName())) {
					return externalLocation;
				}
			}
		}

		return null;
	}

	private List<ExternalLocation> getExternalLocations(Namespace library) {
		List<ExternalLocation> list = new ArrayList<>();
		SymbolIterator iter = symbolMgr.getSymbols(library);
		for (Symbol symbol : iter) {
			ExternalLocation extLoc = getExternalLocation(symbol);
			if (extLoc != null) {
				list.add(extLoc);
			}
		}
		return list;
	}

	// Find an external location in the given namespace with the given name and address.  If
	// reuseExisting is true, then also find a match as long as the name and namespace match and
	// the address is null.
	private ExternalLocation findMatchingLocationByName(Namespace libScope, String extLabel,
			Address extAddr, boolean reuseExisting) {
		if (extLabel == null) {
			return null;
		}

		List<ExternalLocation> externalLocations = getExternalLocations(libScope, extLabel);
		if (externalLocations.isEmpty()) {
			return null;
		}

		if (extAddr != null) {
			// try and find an exact match on address
			for (ExternalLocation externalLocation : externalLocations) {
				if (extAddr.equals(externalLocation.getAddress())) {
					return externalLocation;
				}
			}
			// if reuse existing, return one without an address
			if (reuseExisting) {
				for (ExternalLocation externalLocation : externalLocations) {
					if (externalLocation.getAddress() == null) {
						return externalLocation;
					}
				}
			}
			return null;
		}

		// first look for one without an address
		for (ExternalLocation externalLocation : externalLocations) {
			if (externalLocation.getAddress() == null) {
				return externalLocation;
			}
		}

		// if reuse existing, then return any
		return reuseExisting ? externalLocations.get(0) : null;
	}

	// Look through all the locations for one whose address matches the given address AND whose
	// label is null or reuseExisting is true.  This method only gets called when creating a new
	// location with a non-null address and a null label.  So an exact match is when the address
	// matches and the label is null.  If reuseExisting, then we are trying to find and suitable
	// location, so as long as the address matches, we can return it.
	private ExternalLocation findMatchingLocationByAddress(List<ExternalLocation> locations,
			Address extAddr, boolean reuseExisting) {
		for (ExternalLocation externalLocation : locations) {
			if (extAddr.equals(externalLocation.getAddress())) {
				if (reuseExisting || externalLocation.getLabel() == null) {
					return externalLocation;
				}
			}
		}
		return null;
	}

	@Override
	public List<ExternalLocation> getExternalLocations(Namespace libScope, String extLabel) {
		List<ExternalLocation> externalLocations = new ArrayList<>();
		List<Symbol> symbols = symbolMgr.getSymbols(extLabel, libScope);
		for (Symbol symbol : symbols) {
			ExternalLocation externalLocation = getExternalLocation(symbol);
			if (externalLocation != null) {
				externalLocations.add(externalLocation);
			}
		}
		return externalLocations;
	}

	@Override
	public List<ExternalLocation> getExternalLocations(String libraryName, String label) {
		Namespace libraryScope = getLibraryScope(libraryName);
		if (libraryScope == null) {
			return Collections.emptyList();
		}
		return getExternalLocations(libraryScope, label);
	}

	@Override
	public ExternalLocation getUniqueExternalLocation(Namespace namespace, String label) {
		List<ExternalLocation> externalLocations = getExternalLocations(namespace, label);
		if (externalLocations.size() == 1) {
			return externalLocations.get(0);
		}
		return null;
	}

	@Override
	public ExternalLocation getUniqueExternalLocation(String libraryName, String label) {
		Namespace libScope = getLibraryScope(libraryName);
		if (libScope == null) {
			return null;
		}
		return getUniqueExternalLocation(libScope, label);
	}

	@Override
	public ExternalLocation getExternalLocation(String extName, String extLabel) {
		Namespace libScope = getLibraryScope(extName);
		return getExternalLocation(libScope, extLabel);
	}

	@Override
	public ExternalLocation getExternalLocation(Namespace extNamespace, String extLabel) {
		List<ExternalLocation> externalLocations = getExternalLocations(extNamespace, extLabel);
		if (externalLocations.isEmpty()) {
			return null;
		}
		return externalLocations.get(0);
	}

	/**
	 * Get the default name for an external function or code symbol
	 * @param sym
	 * @return default name
	 */
	public static String getDefaultExternalName(SymbolDB sym) {
		SymbolType type = sym.getSymbolType();
		if ((type != SymbolType.LABEL && type != SymbolType.FUNCTION) || !sym.isExternal()) {
			throw new AssertException();
		}
		ExternalData externalData = ExternalLocationDB.getExternalData(sym);
		Address addr = externalData.getAddress(sym.getProgram().getAddressFactory());
		if (addr == null) {
			throw new AssertException("External should not be default without memory address");
		}
		if (type == SymbolType.FUNCTION) {
			return SymbolUtilities.getDefaultExternalFunctionName(addr);
		}
		long dataTypeID = sym.getDataTypeId();
		DataType dt =
			(dataTypeID < 0) ? null : sym.getProgram().getDataTypeManager().getDataType(dataTypeID);
		return SymbolUtilities.getDefaultExternalName(addr, dt);
	}

	ProgramDB getProgram() {
		return program;
	}

	/**
	 * Returns the external location associated with the given external address
	 * @param externalAddr the external address.
	 */
	public ExternalLocation getExtLocation(Address externalAddr) {
		if (externalAddr.getAddressSpace() != AddressSpace.EXTERNAL_SPACE) {
			throw new IllegalArgumentException("Expected external address");
		}
		lock.acquire();
		try {
			Symbol[] symbols = symbolMgr.getSymbols(externalAddr);
			if (symbols.length == 1) {
				return new ExternalLocationDB(this, (SymbolDB) symbols[0]);
			}
			if (symbols.length > 2) {
				throw new AssertException(
					"More than two symbols are not expected for external addresses: " +
						externalAddr);
			}
			return null;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public ExternalLocation getExternalLocation(Symbol symbol) {
		if (!(symbol instanceof SymbolDB) || !symbol.isExternal()) {
			return null;
		}

		SymbolType symbolType = symbol.getSymbolType();
		if (symbolType == SymbolType.LABEL || symbolType == SymbolType.FUNCTION) {
			return getExtLocation(symbol.getAddress());
		}

		return null;
	}

	/**
	 * Removes the external location at the given external address
	 * @param externalAddr the address at which to remove the external location.
	 */
	public boolean removeExternalLocation(Address externalAddr) {
		lock.acquire();
		try {
			ExternalLocationDB loc = (ExternalLocationDB) getExtLocation(externalAddr);
			if (loc != null) {
				loc.getSymbol().delete();
				return true;
			}
		}
		finally {
			lock.release();
		}
		return false;
	}

	SymbolManager getSymbolManager() {
		return symbolMgr;
	}

	/**
	 * @see ghidra.program.model.symbol.ExternalManager#removeExternalLibrary(java.lang.String)
	 */
	@Override
	public boolean removeExternalLibrary(String name) {
		lock.acquire();
		try {
			Symbol s = symbolMgr.getLibrarySymbol(name);
			if (s != null) {
				if (symbolMgr.getChildren(s).hasNext()) {
					return false;
				}
				s.delete();
			}
		}
		finally {
			lock.release();
		}
		return true;
	}

	/**
	 * Update the external program for all references.
	 * @param oldName old external program name
	 * @param newName new external program name
	 * @param source the source of this external library:
	 * Symbol.DEFAULT, Symbol.ANALYSIS, Symbol.IMPORTED, or Symbol.USER_DEFINED
	 * @throws DuplicateNameException
	 * @throws InvalidInputException
	 */
	@Override
	public void updateExternalLibraryName(String oldName, String newName, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		Symbol s = symbolMgr.getLibrarySymbol(oldName);
		if (s != null) {
			s.setName(newName, source);
		}
	}

	@Override
	public Library addExternalLibraryName(String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		lock.acquire();
		try {
			Symbol librarySymbol = symbolMgr.getLibrarySymbol(name);
			if (librarySymbol != null) {
				return (Library) librarySymbol.getObject();
			}
			return addExternalName(name, null, source);
		}
		finally {
			lock.release();
		}
	}

	private Library addExternalName(String name, String pathname, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		SymbolDB s = symbolMgr.createSpecialSymbol(Address.NO_ADDRESS, name,
			scopeMgr.getGlobalNamespace(), SymbolType.LIBRARY, null, null, pathname, source);
		return (Library) s.getObject();
	}

	private Namespace getLibraryScope(String name) {
		Symbol s = symbolMgr.getLibrarySymbol(name);
		return s == null ? null : (Namespace) s.getObject();
	}

	/**
	 * @see ghidra.program.model.symbol.ExternalManager#contains(java.lang.String)
	 */
	@Override
	public boolean contains(String libraryName) {
		return symbolMgr.getLibrarySymbol(libraryName) != null;
	}

	/**
	 * @see ghidra.program.model.symbol.ExternalManager#getExternalLibraryNames()
	 */
	@Override
	public String[] getExternalLibraryNames() {
		ArrayList<String> list = new ArrayList<>();
		Symbol[] syms = symbolMgr.getSymbols(Address.NO_ADDRESS);
		for (Symbol s : syms) {
			if (s.getSymbolType() == SymbolType.LIBRARY) {
				list.add(s.getName());
			}
		}
		String[] names = new String[list.size()];
		list.toArray(names);
		return names;
	}

	@Override
	public Library getExternalLibrary(String name) {
		Symbol s = symbolMgr.getLibrarySymbol(name);
		return s != null ? (Library) s.getObject() : null;
	}

	/**
	 * @see ghidra.program.model.symbol.ExternalManager#getExternalLibraryPath(java.lang.String)
	 */
	@Override
	public String getExternalLibraryPath(String externalName) {
		SymbolDB s = (SymbolDB) symbolMgr.getLibrarySymbol(externalName);
		if (s instanceof LibrarySymbol) {
			return s.getSymbolStringData();
		}
		return null;
	}

	@Override
	public void setExternalPath(String externalName, String externalPath, boolean userDefined)
			throws InvalidInputException {

		if (Library.UNKNOWN.equals(externalName)) {
			Msg.warn(this, "Ignoring external library path for " + externalName);
			return;
		}

		validateExternalPath(externalPath);

		lock.acquire();
		try {
			SymbolDB s = (SymbolDB) symbolMgr.getLibrarySymbol(externalName);
			if (s == null) {
				try {
					addExternalName(externalName, externalPath,
						userDefined ? SourceType.USER_DEFINED : SourceType.IMPORTED);
				}
				catch (DuplicateNameException e) {
					throw new AssertException(e);
				}
			}
			else if (s instanceof LibrarySymbol) {
				s.setSymbolStringData(externalPath);
			}
		}
		finally {
			lock.release();
		}
	}

	private void validateExternalPath(String path) throws InvalidInputException {
		if (path == null) {
			return; // null is an allowed value (used to clear)
		}

		int len = path.length();
		if (len == 0 || path.charAt(0) != FileSystem.SEPARATOR_CHAR) {
			throw new InvalidInputException(
				"Absolute path must begin with '" + FileSystem.SEPARATOR_CHAR + "'");
		}
	}

	Function createFunction(ExternalLocationDB extLoc) {
		if (extLoc.isFunction()) {
			return extLoc.getFunction();
		}
		lock.acquire();
		try {
			SymbolDB symbol = (SymbolDB) extLoc.getSymbol();
			if (!(symbol instanceof CodeSymbol)) {
				return null;
			}
			//long dtId = symbol.getSymbolData1();
			String extData = symbol.getSymbolStringData();
			String name = symbol.getName();
			Namespace namespace = symbol.getParentNamespace();
			Address extAddr = symbol.getAddress();
			SourceType source = symbol.getSource();

			((CodeSymbol) symbol).delete(true);

			return functionMgr.createExternalFunction(extAddr, name, namespace, extData, source);
		}
		catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException("Unexpected exception", e);
		}
		finally {
			lock.release();
		}

	}

	/**
	 * @return
	 */
	AddressMap getAddressMap() {
		return addrMap;
	}

	@Override
	public ExternalLocationIterator getExternalLocations(Address memoryAddress) {
		return new ExternalLocationDBIterator(symbolMgr.getExternalSymbols(), memoryAddress);
	}

	/**
	 * @see ghidra.program.model.symbol.ExternalManager#getExternalLocations(java.lang.String)
	 */
	@Override
	public ExternalLocationIterator getExternalLocations(String externalName) {
		Namespace scope = getLibraryScope(externalName);
		if (scope != null) {
			return new ExternalLocationDBIterator(symbolMgr.getSymbols(scope));
		}
		return new ExternalLocationDBIterator();
	}

	private class ExternalLocationDBIterator implements ExternalLocationIterator {

		private SymbolIterator symIter;
		private Address matchingAddress;
		private ExternalLocation nextExtLoc;

		ExternalLocationDBIterator() {
		}

		ExternalLocationDBIterator(SymbolIterator symIter, Address matchingAddress) {
			this.symIter = symIter;
			this.matchingAddress = matchingAddress;
		}

		ExternalLocationDBIterator(SymbolIterator symIter) {
			this.symIter = symIter;
		}

		/**
		 * @see java.util.Iterator#remove()
		 */
		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		private ExternalLocation getValidExternalLocation(SymbolDB s) {
			ExternalLocation externalLocation = getExternalLocation(s);
			if (externalLocation == null) {
				return null;
			}

			if (matchingAddress == null) {
				return externalLocation;
			}

			if (matchingAddress.equals(externalLocation.getAddress())) {
				return externalLocation;
			}
			return null;
		}

		/**
		 * @see ghidra.program.model.symbol.ExternalLocationIterator#hasNext()
		 */
		@Override
		public boolean hasNext() {
			if (symIter != null) {
				while (nextExtLoc == null && symIter.hasNext()) {
					SymbolDB s = (SymbolDB) symIter.next();
					nextExtLoc = getValidExternalLocation(s);
				}
			}
			return nextExtLoc != null;
		}

		/**
		 * @see ghidra.program.model.symbol.ExternalLocationIterator#next()
		 */
		@Override
		public ExternalLocation next() {
			if (hasNext()) {
				ExternalLocation tmpExtLoc = nextExtLoc;
				nextExtLoc = null;
				return tmpExtLoc;
			}
			return null;
		}

	}

	public void setLanguage(LanguageTranslator translator, TaskMonitor monitor)
			throws CancelledException {

		monitor.setMessage("Translate External Addresses...");

		AddressFactory oldAddrFactory = translator.getOldLanguage().getAddressFactory();
		SymbolIterator externalSymbols = symbolMgr.getExternalSymbols();
		while (externalSymbols.hasNext()) {
			monitor.checkCanceled();
			SymbolDB s = (SymbolDB) externalSymbols.next();
			ExternalData externalData = ExternalLocationDB.getExternalData(s);
			String addrStr = externalData.getAddressString();
			if (addrStr == null) {
				continue;
			}
			// skip addresses which do not parse by old language - could be
			// overlay (although this should generally never occur)
			Address addr = oldAddrFactory.getAddress(addrStr);
			if (addr == null) {
				continue;
			}
			AddressSpace newAddressSpace =
				translator.getNewAddressSpace(addr.getAddressSpace().getName());
			if (newAddressSpace == null || !newAddressSpace.isLoadedMemorySpace()) {
				// can't really recover from this
				throw new AssertException("Failed to map external memory address: " + addrStr);
			}
			addr = newAddressSpace.getAddress(addr.getOffset());
			String newAddrStr = addr.toString();
			if (!newAddrStr.equals(addrStr)) {
				ExternalLocationDB.updateSymbolData(s, externalData.getOriginalImportedName(),
					newAddrStr); // store translated external location address
			}
		}
	}

	SymbolDB createSymbolForOriginalName(Address address, Namespace namespace, String oldName,
			SourceType oldType) throws InvalidInputException {
		return (SymbolDB) symbolMgr.createCodeSymbol(address, oldName, namespace, oldType, null);
	}

}
