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

import org.apache.commons.lang3.StringUtils;

import db.*;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ManagerDB;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.function.FunctionDB;
import ghidra.program.database.function.FunctionManagerDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.symbol.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Library;
import ghidra.program.model.symbol.*;
import ghidra.util.Lock;
import ghidra.util.Lock.Closeable;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Manages the database for external references.
 */
public class ExternalManagerDB implements ManagerDB, ExternalManager {

	private AddressMap addrMap;
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
	public ExternalManagerDB(DBHandle handle, AddressMap addrMap, OpenMode openMode, Lock lock,
			TaskMonitor monitor) throws CancelledException, IOException, VersionException {

		this.addrMap = addrMap;
		this.lock = lock;
		initializeOldAdapters(handle, openMode, monitor);
	}

	private void initializeOldAdapters(DBHandle handle, OpenMode openMode, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		try {
			// Try old adapters needed for upgrade
			oldNameAdapter = OldExtNameAdapter.getAdapter(handle, openMode, monitor);
			oldExtRefAdapter = OldExtRefAdapter.getAdapter(handle, openMode, monitor);
		}
		catch (VersionException ve) {
			//ignore
		}
		if (oldNameAdapter != null && oldExtRefAdapter != null && openMode != OpenMode.UPGRADE) {
			throw new VersionException(true);
		}
	}

	@Override
	public void setProgram(ProgramDB program) {
		this.program = program;
		symbolMgr = program.getSymbolTable();
		functionMgr = program.getFunctionManager();
	}

	@Override
	public void programReady(OpenMode openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (openMode != OpenMode.UPGRADE) {
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
			monitor.checkCancelled();
			DBRecord rec = iter.next();

			String name = rec.getString(OldExtNameAdapter.EXT_NAME_COL);
			try {
				doAddExternalName(name, rec.getString(OldExtNameAdapter.EXT_PATHNAME_COL),
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
			monitor.checkCancelled();
			DBRecord rec = iter.next();

			Address fromAddr =
				oldAddrMap.decodeAddress(rec.getLongValue(OldExtRefAdapter.FROM_ADDR_COL));
			int opIndex = rec.getShortValue(OldExtRefAdapter.OP_INDEX_COL);
			boolean userDefined = rec.getBooleanValue(OldExtRefAdapter.USER_DEFINED_COL);
			String extLibraryName = nameMap.get(rec.getLongValue(OldExtRefAdapter.EXT_NAME_ID_COL));
			if (extLibraryName == null) {
				continue; // should not happen
			}
			String label = rec.getString(OldExtRefAdapter.LABEL_COL);
			Address addr = rec.getBooleanValue(OldExtRefAdapter.EXT_ADDR_EXISTS_COL)
					? oldAddrMap.decodeAddress(rec.getLongValue(OldExtRefAdapter.EXT_TO_ADDR_COL))
					: null;

			try {
				refMgr.addExternalReference(fromAddr, extLibraryName, label, addr,
					userDefined ? SourceType.USER_DEFINED : SourceType.IMPORTED, opIndex,
					RefType.DATA);
			}
			catch (InvalidInputException | DuplicateNameException e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}
			monitor.setProgress(++cnt);
		}
		oldExtRefAdapter = null;
		return true;
	}

	@Override
	public void invalidateCache(boolean all) throws IOException {
		// nothing to do here
	}

	@Override
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		// Has no affect on externals
	}

	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		// Has no affect on externals
	}

	@Override
	public ExternalLocation addExtLocation(String extLibraryName, String extLabel, Address extAddr,
			SourceType sourceType) throws InvalidInputException, DuplicateNameException {
		SourceType locSourceType = checkExternalLabel(extLabel, extAddr, sourceType);
		try (Closeable c = lock.write()) {
			Library library = addExternalLibraryName(extLibraryName, sourceType);
			return addExtLocation(library, extLabel, extAddr, false, locSourceType, true);
		}
	}

	@Override
	public ExternalLocation addExtLocation(Namespace extParentNamespace, String extLabel,
			Address extAddr, SourceType sourceType) throws InvalidInputException {
		try (Closeable c = lock.write()) {
			return addExtLocation(extParentNamespace, extLabel, extAddr, false, sourceType, true);
		}
	}

	@Override
	public ExternalLocation addExtLocation(Namespace extParentNamespace, String extLabel,
			Address extAddr, SourceType sourceType, boolean reuseExisting)
			throws InvalidInputException {
		try (Closeable c = lock.write()) {
			return addExtLocation(extParentNamespace, extLabel, extAddr, false, sourceType,
				reuseExisting);
		}
	}

	@Override
	public ExternalLocation addExtFunction(String extLibraryName, String extLabel, Address extAddr,
			SourceType sourceType) throws InvalidInputException, DuplicateNameException {
		SourceType locSourceType = checkExternalLabel(extLabel, extAddr, sourceType);
		try (Closeable c = lock.write()) {
			Library library = addExternalLibraryName(extLibraryName,
					sourceType != SourceType.DEFAULT ? sourceType : SourceType.ANALYSIS);
			return addExtLocation(library, extLabel, extAddr, true, locSourceType, true);
		}
	}

	@Override
	public ExternalLocation addExtFunction(Namespace extParentNamespace, String extLabel,
			Address extAddr, SourceType sourceType) throws InvalidInputException {
		try (Closeable c = lock.write()) {
			return addExtLocation(extParentNamespace, extLabel, extAddr, true, sourceType, true);
		}
	}

	@Override
	public ExternalLocation addExtFunction(Namespace extNamespace, String extLabel, Address extAddr,
			SourceType sourceType, boolean reuseExisting) throws InvalidInputException {
		try (Closeable c = lock.write()) {
			return addExtLocation(extNamespace, extLabel, extAddr, true, sourceType, reuseExisting);
		}
	}

	private SourceType checkExternalLabel(String extLabel, Address extAddr, SourceType source)
			throws InvalidInputException {
		if (StringUtils.isBlank(extLabel) ||
			SymbolUtilities.isReservedExternalDefaultName(extLabel, addrMap.getAddressFactory())) {
			extLabel = null; // force use of address
		}
		if (extLabel == null && extAddr == null) {
			throw new InvalidInputException("Either an external label or address is required");
		}
		return extLabel == null ? SourceType.DEFAULT : source;
	}

	private ExternalLocation addExtLocation(Namespace extNamespace, String extLabel,
			Address extAddr, boolean isFunction, SourceType sourceType, boolean reuseExisting)
			throws InvalidInputException {
		if (extNamespace == null) {
			try {
				extNamespace = addExternalLibraryName(Library.UNKNOWN, SourceType.ANALYSIS);
			}
			catch (InvalidInputException | DuplicateNameException e) {
				throw new AssertionError(e); // reserved name should be OK
			}
		}
		else if (!extNamespace.isExternal()) {
			throw new InvalidInputException("The namespace must be an external namespace.");
		}
		sourceType = checkExternalLabel(extLabel, extAddr, sourceType);
		if (extAddr != null) {
			if (!extAddr.isLoadedMemoryAddress()) {
				throw new InvalidInputException("Invalid memory address: " + extAddr);
			}
			AddressSpace space = extAddr.getAddressSpace();
			if (!space.equals(program.getAddressFactory().getAddressSpace(space.getName()))) {
				throw new InvalidInputException(
					"Memory address not defined for program: " + extAddr);
			}
		}
		try (Closeable c = lock.write()) {
			if (sourceType == SourceType.DEFAULT) {
				extLabel = null;
			}
			else if (StringUtils.isBlank(extLabel) || SymbolUtilities
					.isReservedExternalDefaultName(extLabel, addrMap.getAddressFactory())) {
				extLabel = null; // force use of address
			}
			if (extAddr != null || reuseExisting) {

				ExternalLocationDB extLoc = (ExternalLocationDB) getExtLocation(extNamespace,
					extLabel, extAddr, reuseExisting);

				if (extLoc != null) {

					// if there is already a location with the address, then we must use it
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
			MemorySymbol s;
			Address externalSpaceAddress = symbolMgr.getNextExternalSymbolAddress();
			if (isFunction) {
				FunctionDB function = functionMgr.createExternalFunction(externalSpaceAddress,
					extLabel, extNamespace, null, extAddr, sourceType);
				s = (FunctionSymbol) function.getSymbol();
			}
			else {
				s = symbolMgr.createExternalCodeSymbol(externalSpaceAddress, extLabel, extNamespace,
					sourceType, null, extAddr);
			}
			return new ExternalLocationDB(this, s);
		}
		catch (IOException e) {
			program.dbError(e); // will not return
			return null;
		}
	}

	/**
	 * Get the external location which best matches the specified parameters.
	 * Preference is given to extLabel over extAddr
	 * @param library the library namespace containing this external location.
	 * @param extLabel the name of the external location. Can be null.
	 * @param extAddr the address of function in the external program.  Can be null
	 * @return the best matching ExternalLocation or null.
	 * @throws InvalidInputException if the extLabel name contains illegal characters (i.e. space)
	 */
	private ExternalLocation getExtLocation(Namespace library, String extLabel, Address extAddr,
			boolean reuseExisting) throws InvalidInputException {

		// Name match will also consider original import name if library is either null
		// or a Library, otherwise only a specific namespaced name match will be considered.
		ExternalLocation match =
			findMatchingLocationByName(library, extLabel, extAddr, reuseExisting);
		if (match != null) {
			return match;
		}

		if (extLabel == null) { // assume extAddr is not null (already checked)
			return findMatchingLocationByAddress(extAddr, reuseExisting);
		}

		return null;
	}

	// Find an external location in the given namespace with the given name and address.  If
	// reuseExisting is true, then also find a match as long as the name and namespace match and
	// the address is null.
	private ExternalLocation findMatchingLocationByName(Namespace namespace, String extLabel,
			Address extAddr, boolean reuseExisting) {
		if (StringUtils.isBlank(extLabel)) {
			return null;
		}

		Set<ExternalLocation> externalLocations = getExternalLocations(namespace, extLabel);
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
		ExternalLocation possibleExtLoc = null;
		for (ExternalLocation externalLocation : externalLocations) {
			if (externalLocation.getAddress() == null) {
				return externalLocation;
			}
			possibleExtLoc = externalLocation;
		}

		// if reuse existing, then return any
		return reuseExisting ? possibleExtLoc : null;
	}

	// Look through all the locations for one whose address matches the given address AND whose
	// label is null or reuseExisting is true.  This method only gets called when creating a new
	// location with a non-null address and a null label.  So an exact match is when the address
	// matches and the label is null.  If reuseExisting, then we are trying to find and suitable
	// location, so as long as the address matches, we can return it.
	private ExternalLocation findMatchingLocationByAddress(Address extAddr, boolean reuseExisting) {
		for (Symbol symbol : symbolMgr.getExternalSymbolByMemoryAddress(null, extAddr)) {
			ExternalLocation externalLocation = getExternalLocation(symbol);
			if (reuseExisting || externalLocation.getLabel() == null) {
				return externalLocation;
			}
		}
		return null;
	}

	@Override
	public Set<ExternalLocation> getExternalLocations(Namespace namespace, String extLabel) {
		if (namespace != null && !namespace.isExternal()) {
			return Set.of();
		}
		Set<ExternalLocation> externalLocations = new HashSet<>();
		if (namespace == null || namespace instanceof Library) {
			// Check for matching original import name
			SymbolIterator matchingSymbols =
				symbolMgr.getExternalSymbolByOriginalImportName((Library) namespace, extLabel);
			for (Symbol symbol : matchingSymbols) {
				ExternalLocation externalLocation = getExternalLocation(symbol);
				if (externalLocation != null) {
					externalLocations.add(externalLocation);
				}
			}
		}
		if (namespace != null) {
			List<Symbol> symbols = symbolMgr.getSymbols(extLabel, namespace);
			for (Symbol symbol : symbols) {
				ExternalLocation externalLocation = getExternalLocation(symbol);
				if (externalLocation != null) {
					externalLocations.add(externalLocation);
				}
			}
		}
		else {
			for (Symbol symbol : symbolMgr.getExternalSymbols(extLabel)) {
				ExternalLocation externalLocation = getExternalLocation(symbol);
				if (externalLocation != null) {
					externalLocations.add(externalLocation);
				}
			}
		}
		return Collections.unmodifiableSet(externalLocations);
	}

	@Override
	public Set<ExternalLocation> getExternalLocations(String libraryName, String label) {
		Library library = getExternalLibrary(libraryName);
		if (library == null && !StringUtils.isBlank(libraryName)) {
			return Set.of();
		}
		return getExternalLocations(library, label);
	}

	@Override
	public ExternalLocation getUniqueExternalLocation(Namespace namespace, String label) {
		Set<ExternalLocation> externalLocations = getExternalLocations(namespace, label);
		if (externalLocations.size() == 1) {
			return externalLocations.iterator().next();
		}
		return null;
	}

	@Override
	public ExternalLocation getUniqueExternalLocation(String libraryName, String label) {
		Library library = getExternalLibrary(libraryName);
		if (library == null && !StringUtils.isBlank(libraryName)) {
			return null;
		}
		return getUniqueExternalLocation(library, label);
	}

	/**
	 * {@return the default name for an external function or code symbol}
	 * @param sym external label or function symbol
	 * @throws IllegalArgumentException if external label or function symbol not specified or 
	 * external symbol does not have an external program address. 
	 */
	public static String getDefaultExternalName(SymbolDB sym) {
		if (!(sym instanceof MemorySymbol) && !sym.isExternal()) {
			throw new IllegalArgumentException("External label or function symbol required");
		}

		Address addr = ((MemorySymbol) sym).getExternalProgramAddress();
		if (addr == null) {
			throw new IllegalArgumentException("Default External requires memory address");
		}

		if (sym instanceof FunctionSymbol) {
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
	 * {@return the external location associated with the given external address or null}
	 * @param externalAddr the external address.
	 * @throws IllegalArgumentException if address is not external
	 */
	public ExternalLocation getExtLocation(Address externalAddr) {
		if (externalAddr.getAddressSpace() != AddressSpace.EXTERNAL_SPACE) {
			throw new IllegalArgumentException("Expected external address");
		}
		try (Closeable c = lock.read()) {
			Symbol[] symbols = symbolMgr.getSymbols(externalAddr);
			if (symbols.length == 1) {
				return new ExternalLocationDB(this, (MemorySymbol) symbols[0]);
			}
			if (symbols.length > 2) {
				throw new AssertException(
					"More than two symbols are not expected for external addresses: " +
						externalAddr);
			}
			return null;
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
	 * @return true if external location was successfully removed else false
	 */
	public boolean removeExternalLocation(Address externalAddr) {
		try (Closeable c = lock.write()) {
			ExternalLocationDB loc = (ExternalLocationDB) getExtLocation(externalAddr);
			if (loc != null) {
				loc.getSymbol().delete();
				return true;
			}
		}
		return false;
	}

	SymbolManager getSymbolManager() {
		return symbolMgr;
	}

	@Override
	public boolean removeExternalLibrary(String name) {
		try (Closeable c = lock.write()) {
			Symbol s = symbolMgr.getLibrarySymbol(name);
			if (s != null) {
				if (symbolMgr.getChildren(s).hasNext()) {
					return false;
				}
				s.delete();
			}
		}
		return true;
	}

	@Override
	public boolean updateExternalLibraryName(String oldName, String newName, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		try (Closeable c = lock.write()) {
			Symbol s = symbolMgr.getLibrarySymbol(oldName);
			if (s != null) {
				s.setName(newName, source);
				return true;
			}
		}
		return false;
	}

	@Override
	public Library addExternalLibraryName(String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		try (Closeable c = lock.write()) {
			Symbol librarySymbol = symbolMgr.getLibrarySymbol(name);
			if (librarySymbol != null) {
				return (Library) librarySymbol.getObject();
			}
			return doAddExternalName(name, null, source);
		}
	}

	private Library doAddExternalName(String name, String pathname, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		SymbolDB s = symbolMgr.createLibrarySymbol(name, pathname, source);
		return (Library) s.getObject();
	}

	@Override
	public boolean contains(String libraryName) {
		return symbolMgr.getLibrarySymbol(libraryName) != null;
	}

	@Override
	public List<Library> getLibraries() {
		try (Closeable c = lock.read()) {
			List<Library> orderedLibraries = new ArrayList<>();
			for (LibrarySymbol libSym : symbolMgr.getLibrarySymbolList()) {
				orderedLibraries.add(libSym.getObject());
			}
			return orderedLibraries;
		}
	}

	@Override
	public String[] getExternalLibraryNames() {
		ArrayList<String> list = new ArrayList<>();
		for (LibrarySymbol libSym : symbolMgr.getLibrarySymbolList()) {
			list.add(libSym.getName());
		}
		String[] names = new String[list.size()];
		list.toArray(names);
		return names;
	}

	@Override
	public Library getExternalLibrary(String name) {
		try (Closeable c = lock.read()) {
			Symbol s = symbolMgr.getLibrarySymbol(name);
			return s != null ? (Library) s.getObject() : null;
		}
	}

	@Override
	public String getExternalLibraryPath(String externalName) {
		LibrarySymbol s = symbolMgr.getLibrarySymbol(externalName);
		if (s != null) {
			return s.getExternalLibraryPath();
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

		LibrarySymbol.validateExternalPath(externalPath);

		try (Closeable c = lock.write()) {
			Library library = addExternalLibraryName(externalName,
				userDefined ? SourceType.USER_DEFINED : SourceType.IMPORTED);
			LibrarySymbol libSym = (LibrarySymbol) library.getSymbol();
			libSym.setExternalLibraryPath(externalPath);
		}
		catch (DuplicateNameException e) {
			// ignore - new externalName conflicts with another namespace
		}
	}

	@Override
	public int getLibraryOrdinal(String libraryName) {
		LibrarySymbol libSym = symbolMgr.getLibrarySymbol(libraryName);
		return libSym != null ? libSym.getOrdinal() : -1;
	}

	@Override
	public int setLibraryOrdinal(String libraryName, int ordinal) {
		if (Library.UNKNOWN.equals(libraryName)) {
			Msg.warn(this, "Ignoring external library ordinal assignment for " + libraryName);
			return -1;
		}
		try (Closeable c = lock.write()) {
			LibrarySymbol libSym = symbolMgr.getLibrarySymbol(libraryName);
			if (libSym == null) {
				return -1;
			}
			libSym.setOrdinal(ordinal);
			return libSym.getOrdinal();
		}
	}

	Function createFunction(ExternalLocationDB extLoc) {
		if (extLoc.isFunction()) {
			return extLoc.getFunction();
		}
		try (Closeable c = lock.write()) {
			SymbolDB symbol = (SymbolDB) extLoc.getSymbol();
			if (!(symbol instanceof CodeSymbol)) {
				throw new IllegalStateException("Expected external code symbol");
			}
			Address extProgAddr = extLoc.getAddress();
			String origImpName = extLoc.getOriginalImportedName();
			String name = symbol.getName();
			Namespace namespace = symbol.getParentNamespace();
			Address extAddr = symbol.getAddress();
			SourceType source = symbol.getSource();

			((CodeSymbol) symbol).delete(true);

			return functionMgr.createExternalFunction(extAddr, name, namespace, origImpName,
				extProgAddr, source);
		}
		catch (Exception e) {
			throw new RuntimeException("Unexpected exception", e);
		}
	}

	AddressMap getAddressMap() {
		return addrMap;
	}

	@Override
	public ExternalLocationIterator getExternalLocations(Address memoryAddress) {
		return new ExternalLocationDBIterator(null, memoryAddress);
	}

	@Override
	public ExternalLocationIterator getExternalLocations(String externalName) {
		Library library = getExternalLibrary(externalName);
		if (library != null) {
			return new ExternalLocationDBIterator(symbolMgr.getSymbols(library));
		}
		return new ExternalLocationDBIterator();
	}

	private class ExternalLocationDBIterator implements ExternalLocationIterator {

		private SymbolIterator symIter;
		private Address matchingAddress;
		private ExternalLocation nextExtLoc;

		ExternalLocationDBIterator() {
		}

		ExternalLocationDBIterator(Library library, Address matchingAddress) {
			this.symIter = symbolMgr.getExternalSymbolByMemoryAddress(library, matchingAddress);
			this.matchingAddress = matchingAddress;
		}

		ExternalLocationDBIterator(SymbolIterator symIter) {
			this.symIter = symIter;
		}

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

}
