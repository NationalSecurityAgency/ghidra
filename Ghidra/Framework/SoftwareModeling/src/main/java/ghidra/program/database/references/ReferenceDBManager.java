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
package ghidra.program.database.references;

import java.io.IOException;
import java.util.*;

import org.apache.commons.collections4.map.LazyMap;
import org.apache.commons.collections4.map.LazySortedMap;

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.*;
import ghidra.program.database.external.ExternalManagerDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ChangeManager;
import ghidra.util.Lock;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Reference manager implementation for the database.
 */
public class ReferenceDBManager implements ReferenceManager, ManagerDB, ErrorHandler {
	private static final Reference[] NO_REFS = new Reference[0];

	private FunctionVariableReferenceCacher functionCacher = new FunctionVariableReferenceCacher();

	private OldStackRefDBAdpater oldStackRefAdapter;
	private AddressMap addrMap;

	private FromAdapter fromAdapter;
	private ToAdapter toAdapter;
	private ProgramDB program;
	private SymbolManager symbolMgr;
	private Lock lock;

	private DBObjectCache<RefList> fromCache;
	private DBObjectCache<RefList> toCache;

	/**
	 *
	 * Construct a new reference manager.
	 * @param dbHandle handle to the database
	 * @param addrMap map to convert addresses to longs and longs to addresses
	 * @param openMode one of ProgramDB.CREATE, UPDATE, UPGRADE, or READ_ONLY
	 * @param lock the program synchronization lock
	 * @param monitor Task monitor for upgrading
	 * @throws CancelledException if the user cancels the loading of this db
	 * @throws IOException if a database io error occurs.
	 * @throws VersionException if the database version is different from the expected version
	 */
	public ReferenceDBManager(DBHandle dbHandle, AddressMap addrMap, int openMode, Lock lock,
			TaskMonitor monitor) throws CancelledException, IOException, VersionException {
		this.addrMap = addrMap;
		this.lock = lock;
		fromCache = new DBObjectCache<>(100);
		toCache = new DBObjectCache<>(100);

		VersionException versionExc = null;
		try {
			initializeAdapters(dbHandle, openMode, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			oldStackRefAdapter = OldStackRefDBAdpater.getAdapter(dbHandle, openMode, monitor);
			if (openMode != DBConstants.UPGRADE) {
				// Upgrade required
				versionExc = (new VersionException(true)).combine(versionExc);
			}
		}
		catch (VersionException e) {
			// Ignore - no longer needed
		}
		if (versionExc != null) {
			throw versionExc;
		}
	}

	private void initializeAdapters(DBHandle handle, int openMode, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		VersionException versionExc = null;
		try {
			fromAdapter = FromAdapter.getAdapter(handle, openMode, addrMap, this, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			toAdapter = ToAdapter.getAdapter(handle, openMode, addrMap, this, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		if (versionExc != null) {
			throw versionExc;
		}
		if (openMode == DBConstants.UPGRADE) {
			// Delete old table which is no longer used
			handle.deleteTable("Memory References");
		}
	}

	@Override
	public void setProgram(ProgramDB program) {
		this.program = program;
		symbolMgr = (SymbolManager) program.getSymbolTable();
	}

	@Override
	public void programReady(int openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (openMode == DBConstants.UPGRADE) {

			// Eliminate old stack references table
			processOldAdapterStackRefs(monitor);

			// Convert old namespace and Variable addresses to normal stack/register addresses.
			// Rely on ProgramDB version change to force this upgrade
			convertOldReferences(monitor);
		}
	}

	/**
	 * Convert old namespace and Variable addresses to normal stack/register addresses.
	 * Relies on ProgramDB version change (Version 12) to trigger upgrade requirement.
	 */
	private void convertOldReferences(TaskMonitor monitor) throws IOException, CancelledException {

		AddressFactory factory = program.getAddressFactory();
		AddressIterator toVarAddresses =
			toAdapter.getToIterator(new AddressSet(AddressSpace.VARIABLE_SPACE.getMinAddress(),
				AddressSpace.VARIABLE_SPACE.getMaxAddress()), true);
		convertOldReferences(toVarAddresses, "Variable", monitor);
		convertOldReferences(toAdapter.getOldNamespaceAddresses(factory.getRegisterSpace()),
			"Register", monitor);
		convertOldReferences(toAdapter.getOldNamespaceAddresses(factory.getStackSpace()), "Stack",
			monitor);

	}

	private void convertOldReferences(AddressIterator toIterator, String typeOfRef,
			TaskMonitor monitor) throws IOException, CancelledException {

		int cnt = 0;
		while (toIterator.hasNext()) {
			monitor.checkCanceled();
			Address oldAddr = toIterator.next();
			if (!oldAddr.isVariableAddress() && !(oldAddr instanceof OldGenericNamespaceAddress)) {
				break;
			}
			if (cnt == 0) {
				monitor.setMessage("Converting " + typeOfRef + " References...");
				monitor.initialize(toAdapter.getRecordCount());
			}
			monitor.setProgress(++cnt);

			Address newAddr = null;
			if (oldAddr instanceof OldGenericNamespaceAddress) {
				OldGenericNamespaceAddress oldNamespaceAddr = (OldGenericNamespaceAddress) oldAddr;
				long functionID = oldNamespaceAddr.getNamespaceID();
				Symbol sym = symbolMgr.getSymbol(functionID);
				if (sym != null && sym.getSymbolType() == SymbolType.FUNCTION) {
					newAddr = oldNamespaceAddr.getGlobalAddress();
				}
			}
			else {
				Symbol[] symbols = symbolMgr.getSymbols(oldAddr);
				if (symbols != null && symbols.length != 0) {
					Variable v = (Variable) symbols[0].getObject();
					VariableStorage storage = v.getVariableStorage();
					if (storage != null && !storage.isCompoundStorage()) {
						newAddr = storage.getFirstVarnode().getAddress();
					}
				}
			}

			if (newAddr == null) {
				// This is an unexpected situation
				removeAllTo(oldAddr);
			}
			else {
				moveReferencesTo(oldAddr, newAddr, monitor);
			}
		}

	}

	/**
	 * Remove all references that have the "To" address as
	 * the given address.  NOTE: This method relies on the use of the ToRefs list!
	 * Beyond version-12 of ProgramDB, Stack and Register addresses are no longer stored in the
	 * ToRefs list.
	 * @return number of references removed
	 */
	private int removeAllTo(Address toAddr) throws IOException {
		RefList toRefs = getToRefs(toAddr);
		if (toRefs == null) {
			return 0;
		}
		int cnt = toRefs.getNumRefs();
		Reference[] refs = toRefs.getAllRefs();
		for (Reference ref : refs) {
			RefList fromRefs = getFromRefs(ref.getFromAddress());
			fromRefs.removeRef(toAddr, ref.getOperandIndex());
			if (fromRefs.isEmpty()) {
				fromCache.delete(fromRefs.getKey());
			}
			referenceRemoved(ref);
		}
		toRefs.removeAll();
		toCache.delete(toRefs.getKey());
		return cnt;
	}

	/**
	 * Convert stack references from old adapter.
	 */
	private void processOldAdapterStackRefs(TaskMonitor monitor)
			throws IOException, CancelledException {
		if (oldStackRefAdapter == null) {
			return;
		}

		AddressMap oldAddrMap = addrMap.getOldAddressMap();

		monitor.setMessage("Processing Old Stack References...");
		monitor.initialize(oldStackRefAdapter.getRecordCount());
		int cnt = 0;

		RecordIterator iter = oldStackRefAdapter.getRecords();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			DBRecord rec = iter.next();

			Address fromAddr =
				oldAddrMap.decodeAddress(rec.getLongValue(OldStackRefDBAdpater.FROM_ADDR_COL));
			int opIndex = rec.getShortValue(OldStackRefDBAdpater.OP_INDEX_COL);
			boolean userDefined = rec.getBooleanValue(OldStackRefDBAdpater.USER_DEFINED_COL);
			int offset = rec.getShortValue(OldStackRefDBAdpater.STACK_OFFSET_COL);

			addStackReference(fromAddr, opIndex, offset, RefType.READ,
				(userDefined ? SourceType.USER_DEFINED : SourceType.ANALYSIS));

			monitor.setProgress(++cnt);
		}
		oldStackRefAdapter = null;
	}

	/**
	 * Check an existing reference to determine if there is the possibility of merging
	 * reference-types
	 * @param ref existing reference
	 * @param isOffset true if new reference is an offset reference
	 * @param isShifted true if new reference is a shifted reference
	 * @param offsetOrShift the offset or shift amount 
	 * @return true if incompatible
	 */
	private boolean isIncompatible(Reference ref, boolean isOffset, boolean isShifted,
			long offsetOrShift) {

		if (isShifted != ref.isShiftedReference() || isOffset != ref.isOffsetReference()) {
			return true;
		}

		if (isShifted) {
			return ((ShiftedReference) ref).getShift() != offsetOrShift;
		}
		if (isOffset) {
			return ((OffsetReference) ref).getOffset() != offsetOrShift;
		}
		return false;
	}

	/**
	 * When adding a reference on top of an existing reference, attempt to combine
	 * the reference types giving preference to the most specific type.
	 * @param newType the new type
	 * @param oldType the old type
	 * @return combined reference type, or the newType if unable to combine
	 */
	private RefType combineReferenceType(RefType newType, RefType oldType) {
		if (newType == RefType.DATA) {
			if (oldType.isData()) {
				return oldType;
			}
		}
		if (newType == RefType.DATA_IND) {
			if (oldType.isIndirect()) {
				return oldType;
			}
		}
		else if (newType == RefType.READ) {
			if (oldType == RefType.WRITE || oldType == RefType.READ_WRITE) {
				return RefType.READ_WRITE;
			}
		}
		else if (newType == RefType.WRITE) {
			if (oldType == RefType.READ || oldType == RefType.READ_WRITE) {
				return RefType.READ_WRITE;
			}
		}
		if (newType == RefType.READ_IND) {
			if (oldType == RefType.WRITE_IND || oldType == RefType.READ_WRITE_IND) {
				return RefType.READ_WRITE_IND;
			}
		}
		if (newType == RefType.WRITE_IND) {
			if (oldType == RefType.READ_IND || oldType == RefType.READ_WRITE_IND) {
				return RefType.READ_WRITE_IND;
			}
		}
		return newType;
	}

	private ReferenceDB addRef(Address fromAddr, Address toAddr, RefType type,
			SourceType sourceType, int opIndex, boolean isOffset, boolean isShifted,
			long offsetOrShift) throws IOException {

		if (isOffset && isShifted) {
			throw new IllegalArgumentException("Reference may not be both shifted and offset");
		}

		if (opIndex < Reference.MNEMONIC) {
			throw new IllegalArgumentException("Invalid opIndex specified: " + opIndex);
		}

		if (toAddr.getAddressSpace().isOverlaySpace()) {
			toAddr = ((OverlayAddressSpace) toAddr.getAddressSpace()).translateAddress(toAddr);
		}

		lock.acquire();
		try {
			boolean isPrimary = false;

			ReferenceDB oldRef = (ReferenceDB) getReference(fromAddr, toAddr, opIndex);
			if (oldRef != null) {
				if (!isIncompatible(oldRef, isOffset, isShifted, offsetOrShift)) {
					type = combineReferenceType(type, oldRef.getReferenceType());
					if (type == oldRef.getReferenceType()) {
						return oldRef;
					}
				}
				removeReference(fromAddr, toAddr, opIndex);
				isPrimary = oldRef.isPrimary();
			}

			boolean isStackRegisterRef = toAddr.isStackAddress() || toAddr.isRegisterAddress();

			RefList fromRefs = getFromRefs(fromAddr);
			RefList toRefs = null;
			if (!isStackRegisterRef) {
				toRefs = getToRefs(toAddr);
			}

			//make the 1st reference primary...
			isPrimary |=
				fromRefs == null || (fromAddr.isMemoryAddress() && !fromRefs.hasReference(opIndex));

			if (fromRefs == null) {
				fromRefs = fromAdapter.createRefList(program, fromCache, fromAddr);
			}
			fromRefs = fromRefs.checkRefListSize(fromCache, 1);
			fromRefs.addRef(fromAddr, toAddr, type, opIndex, -1, isPrimary, sourceType, isOffset,
				isShifted, offsetOrShift);

			if (toRefs == null && !isStackRegisterRef) {
				toRefs = toAdapter.createRefList(program, toCache, toAddr);
			}
			if (toRefs != null) {
				toRefs = toRefs.checkRefListSize(toCache, 1);
				toRefs.addRef(fromAddr, toAddr, type, opIndex, -1, isPrimary, sourceType, isOffset,
					isShifted, offsetOrShift);
			}

			ReferenceDB r = toRefs == null || fromRefs.getNumRefs() < toRefs.getNumRefs()
					? fromRefs.getRef(toAddr, opIndex)
					: toRefs.getRef(fromAddr, opIndex);

			referenceAdded(r);
			return r;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Reference addMemoryReference(Address fromAddr, Address toAddr, RefType type,
			SourceType sourceType, int opIndex) {
		if (!fromAddr.isMemoryAddress()) {
			throw new IllegalArgumentException("From address must be memory addresses");
		}
		try {
			if (!toAddr.isMemoryAddress()) {
				removeAllFrom(fromAddr, opIndex);
			}
			else if (toAddr.isMemoryAddress()) {
				removeNonMemRefs(fromAddr, opIndex);
			}
			else {
				throw new IllegalArgumentException("To address must be memory or register address");
			}
			return addRef(fromAddr, toAddr, type, sourceType, opIndex, false, false, 0);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	@Override
	public Reference addStackReference(Address fromAddr, int opIndex, int stackOffset, RefType type,
			SourceType sourceType) {
		if (!fromAddr.isMemoryAddress()) {
			throw new IllegalArgumentException("From address must be memory address");
		}
		Function function = program.getFunctionManager().getFunctionContaining(fromAddr);
		if (function == null) {
			throw new IllegalArgumentException(
				"Invalid stack reference scope: fromAddr not within function");
		}
		removeAllFrom(fromAddr, opIndex);
		try {
			Address stackAddr = program.getAddressFactory().getStackSpace().getAddress(stackOffset);
			return addRef(fromAddr, stackAddr, type, sourceType, opIndex, false, false, 0);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	private void removeNonMemRefs(Address fromAddr, int opIndex) throws IOException {
		if (fromAddr == Address.EXT_FROM_ADDRESS) {
			return;
		}
		RefList fromRefs = getFromRefs(fromAddr);
		if (fromRefs == null) {
			return;
		}
		ReferenceIterator refIter = fromRefs.getRefs();
		while (refIter.hasNext()) {
			Reference ref = refIter.next();
			if (ref.getOperandIndex() == opIndex && !ref.isMemoryReference()) {
				delete(ref);
			}
		}
	}

	@Override
	public Reference addRegisterReference(Address fromAddr, int opIndex, Register register,
			RefType type, SourceType sourceType) {
		if (!fromAddr.isMemoryAddress()) {
			throw new IllegalArgumentException("From address must be memory address");
		}
		removeAllFrom(fromAddr, opIndex);
		try {
			return addRef(fromAddr, register.getAddress(), type, sourceType, opIndex, false, false,
				0);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	@Override
	public Reference addOffsetMemReference(Address fromAddr, Address toAddr, long offset,
			RefType type, SourceType sourceType, int opIndex) {
		if (!fromAddr.isMemoryAddress() || !toAddr.isMemoryAddress()) {
			throw new IllegalArgumentException("From and To addresses must be memory addresses");
		}
		try {
			removeNonMemRefs(fromAddr, opIndex);
			return addRef(fromAddr, toAddr, type, sourceType, opIndex, true, false, offset);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	@Override
	public Reference addShiftedMemReference(Address fromAddr, Address toAddr, int shiftValue,
			RefType type, SourceType sourceType, int opIndex) {
		if (!fromAddr.isMemoryAddress() || !toAddr.isMemoryAddress()) {
			throw new IllegalArgumentException("From and To addresses must be memory addresses");
		}
		try {
			removeNonMemRefs(fromAddr, opIndex);
			return addRef(fromAddr, toAddr, type, sourceType, opIndex, false, true, shiftValue);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	@Override
	public Reference addExternalReference(Address fromAddr, int opIndex, ExternalLocation location,
			SourceType sourceType, RefType type) throws InvalidInputException {
		if (!fromAddr.isMemoryAddress()) {
			throw new IllegalArgumentException("From address must be memory addresses");
		}
		removeAllFrom(fromAddr, opIndex);
		try {
			if (symbolMgr.getPrimarySymbol(location.getExternalSpaceAddress()) != null) {
				return addRef(fromAddr, location.getExternalSpaceAddress(), type, sourceType,
					opIndex, false, false, 0);
			}
			try {
				return addExternalReference(fromAddr, location.getParentName(), location.getLabel(),
					location.getAddress(), sourceType, opIndex, type);
			}
			catch (DuplicateNameException e) {
				throw new InvalidInputException(
					"External location not found and failed to create due to name conflict");
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	@Override
	public Reference addExternalReference(Address fromAddr, String libraryName, String extLabel,
			Address extAddr, SourceType sourceType, int opIndex, RefType type)
			throws InvalidInputException, DuplicateNameException {
		if (libraryName == null || libraryName.length() == 0) {
			throw new InvalidInputException("A valid library name must be specified.");
		}
		if (extLabel != null && extLabel.length() == 0) {
			extLabel = null;
		}
		if (extLabel == null && extAddr == null) {
			throw new InvalidInputException("Either an external label or address is required");
		}
		if (!fromAddr.isMemoryAddress() || (extAddr != null && !extAddr.isMemoryAddress())) {
			throw new IllegalArgumentException(
				"From and extAddr addresses must be memory addresses");
		}
		removeAllFrom(fromAddr, opIndex);
		try {
			ExternalManagerDB extMgr = (ExternalManagerDB) program.getExternalManager();
			ExternalLocation extLoc =
				extMgr.addExtLocation(libraryName, extLabel, extAddr, sourceType);
			Address toAddr = extLoc.getExternalSpaceAddress();

			return addRef(fromAddr, toAddr, type, sourceType, opIndex, false, false, 0);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	@Override
	public Reference addExternalReference(Address fromAddr, Namespace extNamespace, String extLabel,
			Address extAddr, SourceType sourceType, int opIndex, RefType type)
			throws InvalidInputException, DuplicateNameException {
		if (extNamespace == null || !extNamespace.isExternal()) {
			throw new InvalidInputException("The namespace must be an external namespace.");
		}
		if (extLabel != null && extLabel.length() == 0) {
			extLabel = null;
		}
		if (extLabel == null && extAddr == null) {
			throw new InvalidInputException("Either an external label or address is required");
		}
		if (!fromAddr.isMemoryAddress() || (extAddr != null && !extAddr.isMemoryAddress())) {
			throw new IllegalArgumentException(
				"From and extAddr addresses must be memory addresses");
		}
		removeAllFrom(fromAddr, opIndex);
		try {
			ExternalManagerDB extMgr = (ExternalManagerDB) program.getExternalManager();
			ExternalLocation extLoc =
				extMgr.addExtLocation(extNamespace, extLabel, extAddr, sourceType);
			Address toAddr = extLoc.getExternalSpaceAddress();
			return addRef(fromAddr, toAddr, type, sourceType, opIndex, false, false, 0);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	/**
	 * Attempts to determine which if any of the local functions variables are referenced by the specified
	 * reference.  In utilizing the firstUseOffset scoping model, negative offsets (relative to the functions
	 * entry) are shifted beyond the maximum positive offset within the function.  While this does not account for the
	 * actual instruction flow, it is hopefully accurate enough for most situations.
	 * @see ghidra.program.model.symbol.ReferenceManager#getReferencedVariable(ghidra.program.model.symbol.Reference)
	 */
	@Override
	public Variable getReferencedVariable(Reference reference) {
		RefType refType = reference.getReferenceType();
		return program.getFunctionManager()
				.getReferencedVariable(reference.getFromAddress(),
					reference.getToAddress(), 0,
					!refType.isWrite() && (refType.isRead() || refType.isIndirect()));
	}

	/**
	 * Attempts to determine the set of references which refer to the specified variable.
	 * In utilizing the firstUseOffset scoping model, negative offsets (relative to the functions
	 * entry) are shifted beyond the maximum positive offset within the function.  While this does not account for the
	 * actual instruction flow, it is hopefully accurate enough for most situations.
	 * @see ghidra.program.model.symbol.ReferenceManager#getReferencesTo(ghidra.program.model.listing.Variable)
	 */
	@Override
	public Reference[] getReferencesTo(Variable var) {

		lock.acquire();
		try {
			Function function = var.getFunction();
			if (function.getProgram() != program || function.isDeleted()) {
				return NO_REFS;
			}

			SymbolDB varSymbol = (SymbolDB) var.getSymbol();
			if (varSymbol != null && varSymbol.isDeleted()) {
				return NO_REFS;
			}

			functionCacher.setFunction(function);

			VariableStorage storage = var.getVariableStorage();
			Scope scope = findVariableScope(function, varSymbol, var);
			List<Reference> matchingReferences =
				getScopedVariableReferences(storage, function, scope);
			if (matchingReferences.isEmpty()) {
				return NO_REFS;
			}

			Reference[] refs = new Reference[matchingReferences.size()];
			matchingReferences.toArray(refs);
			return refs;
		}
		finally {
			lock.release();
		}
	}

	private Scope findVariableScope(Function function, Symbol varSymbol, Variable var) {

		VariableStorage storage = var.getVariableStorage();
		Address variableAddr = null;
		try {
			variableAddr = (varSymbol != null) ? varSymbol.getAddress()
					: symbolMgr.findVariableStorageAddress(storage);
		}
		catch (IOException e) {
			dbError(e);
		}

		int firstUseOffset = var.getFirstUseOffset();
		int outOfScopeOffset = Integer.MAX_VALUE;
		if (firstUseOffset < 0) {
			firstUseOffset = Integer.MAX_VALUE - firstUseOffset;
		}

		if (variableAddr == null) {
			return new Scope(firstUseOffset, outOfScopeOffset);
		}

		// There could be more than one variable with the same address
		// Determine scope of variable within function
		for (Variable v : functionCacher.getVariables(variableAddr)) {
			int nextVarOffset = v.getFirstUseOffset();
			if (nextVarOffset < 0) {
				nextVarOffset = Integer.MAX_VALUE - nextVarOffset;
			}
			if (nextVarOffset < outOfScopeOffset && nextVarOffset > firstUseOffset) {
				outOfScopeOffset = nextVarOffset;
			}
		}

		return new Scope(var.getFirstUseOffset(), outOfScopeOffset);
	}

	private List<Reference> getScopedVariableReferences(VariableStorage storage,
			Function function, Scope scope) {

		SortedMap<Address, List<Reference>> dataReferences =
			functionCacher.getFunctionDataReferences();

		Address entry = function.getEntryPoint();
		List<Reference> references = new ArrayList<>();
		for (Varnode varnode : storage.getVarnodes()) {
			getScopedVarnodeReferences(references, varnode, dataReferences, scope, entry);
		}

		return references;
	}

	private void getScopedVarnodeReferences(List<Reference> matchingReferences, Varnode varnode,
			SortedMap<Address, List<Reference>> dataReferences, Scope scope, Address entry) {

		Address minStorageAddr = varnode.getAddress();
		Address maxStorageAddr;
		try {
			maxStorageAddr = minStorageAddr.add(varnode.getSize() - 1);
		}
		catch (AddressOutOfBoundsException e) {
			// Data-type too big
			maxStorageAddr = minStorageAddr.getAddressSpace().getMaxAddress();
		}

		int firstUseOffset = scope.getFirstUseOffset();
		int outOfScopeOffset = scope.getOutOfScopeOffset();

		SortedMap<Address, List<Reference>> subMap = dataReferences.tailMap(minStorageAddr);
		Iterator<List<Reference>> refListIter = subMap.values().iterator();
		while (refListIter.hasNext()) {

			List<Reference> refList = refListIter.next();
			for (Reference ref : refList) {

				if (ref.getToAddress().compareTo(maxStorageAddr) > 0) {
					return;
				}
				int refOffset = (int) ref.getFromAddress().subtract(entry);
				if (refOffset < 0) {
					refOffset = Integer.MAX_VALUE - refOffset;
				}
				if (refOffset >= firstUseOffset && refOffset < outOfScopeOffset) {
					// reference is within variable scope - add to list
					matchingReferences.add(ref);
				}
			}
		}
	}

	@Override
	public void setPrimary(Reference ref, boolean isPrimary) {
		lock.acquire();
		try {
			Address fromAddr = ref.getFromAddress();
			Address toAddr = ref.getToAddress();
			int opIndex = ref.getOperandIndex();
			RefList fromRefs = getFromRefs(fromAddr);
			if (fromRefs == null) {
				return;
			}
			Reference pref = isPrimary ? fromRefs.getPrimaryRef(opIndex) : null;
			if (fromRefs.setPrimary(ref, isPrimary)) {
				RefList toRefs = getToRefs(toAddr);
				if (toRefs != null) {
					toRefs.setPrimary(ref, isPrimary);
				}
				if (pref != null) {
					fromRefs.setPrimary(pref, false);
					toRefs = getToRefs(pref.getToAddress());
					if (toRefs != null) {
						toRefs.setPrimary(ref, false);
					}
					referencePrimaryChanged(pref);
				}
				referencePrimaryChanged(ref);
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
	public Reference[] getReferencesFrom(Address addr) {
		lock.acquire();
		try {
			RefList fromRefs = getFromRefs(addr);
			if (fromRefs == null) {
				return NO_REFS;
			}
			return fromRefs.getAllRefs();
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
	public Reference[] getFlowReferencesFrom(Address addr) {
		Reference[] refs = getReferencesFrom(addr);
		ArrayList<Reference> list = new ArrayList<>(refs.length);
		for (Reference ref : refs) {
			if (ref.getReferenceType().isFlow()) {
				list.add(ref);
			}
		}
		refs = new Reference[list.size()];
		return list.toArray(refs);
	}

	@Override
	public Reference getReference(Address fromAddr, Address toAddr, int opIndex) {
		lock.acquire();
		try {
			if (fromAddr.equals(Address.EXT_FROM_ADDRESS)) {
				RefList toRefs = getToRefs(toAddr);
				if (toRefs != null) {
					return toRefs.getRef(fromAddr, opIndex);
				}
			}
			else {
				RefList fromRefs = getFromRefs(fromAddr);
				if (fromRefs != null) {
					return fromRefs.getRef(toAddr, opIndex);
				}
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
	public int getReferenceCountFrom(Address fromAddr) {
		RefList fromRefs = getFromRefs(fromAddr);
		if (fromRefs != null) {
			return fromRefs.getNumRefs();
		}
		return 0;
	}

	@Override
	public int getReferenceCountTo(Address toAddr) {
		if (toAddr.isStackAddress() || toAddr.isRegisterAddress()) {
			throw new UnsupportedOperationException(
				"getReferenceCountTo not supported for stack/register addresses");
		}
		RefList toRefs = getToRefs(toAddr);
		if (toRefs != null) {
			return toRefs.getNumRefs();
		}
		return 0;
	}

	@Override
	public int getReferenceDestinationCount() {
		return toAdapter.getRecordCount();
	}

	@Override
	public int getReferenceSourceCount() {
		return fromAdapter.getRecordCount();
	}

	/**
	 * Get all memory references with the given from address at opIndex.
	 * @param fromAddr the from address
	 * @param opIndex the operand index
	 * @return the references
	 */
	Reference[] getReferences(Address fromAddr, int opIndex) {
		lock.acquire();
		try {
			RefList fromRefs = getFromRefs(fromAddr);
			if (fromRefs == null) {
				return NO_REFS;
			}
			ArrayList<Reference> list = new ArrayList<>(10);
			ReferenceIterator it = fromRefs.getRefs();
			while (it.hasNext()) {
				Reference ref = it.next();
				if (ref.getOperandIndex() == opIndex) {
					list.add(ref);
				}
			}
			Reference[] refs = new Reference[list.size()];
			return list.toArray(refs);
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
	public Reference getPrimaryReferenceFrom(Address addr, int opIndex) {
		lock.acquire();
		try {
			RefList fromRefs = getFromRefs(addr);
			if (fromRefs != null) {
				return fromRefs.getPrimaryRef(opIndex);
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
	public AddressIterator getReferenceDestinationIterator(Address startAddr, boolean forward) {
		try {
			return toAdapter.getToIterator(startAddr, forward);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	@Override
	public AddressIterator getReferenceDestinationIterator(AddressSetView addrSet,
			boolean forward) {
		if (addrSet != null && addrSet.isEmpty()) {
			return AddressIterator.EMPTY_ITERATOR;
		}
		try {
			return toAdapter.getToIterator(addrSet, forward);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	@Override
	public AddressIterator getReferenceSourceIterator(Address startAddr, boolean forward) {
		try {
			return fromAdapter.getFromIterator(startAddr, forward);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	@Override
	public ReferenceIterator getReferenceIterator(Address startAddr) {
		return new FromRefIterator(startAddr);
	}

	@Override
	public AddressIterator getReferenceSourceIterator(AddressSetView addrSet, boolean forward) {
		if (addrSet != null && addrSet.isEmpty()) {
			return AddressIterator.EMPTY_ITERATOR;
		}
		try {
			return fromAdapter.getFromIterator(addrSet, forward);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return new EmptyAddressIterator();
	}

	@Override
	public boolean hasFlowReferencesFrom(Address addr) {
		lock.acquire();
		try {
			RefList fromRefs = getFromRefs(addr);
			if (fromRefs == null) {
				return false;
			}
			ReferenceIterator it = fromRefs.getRefs();
			while (it.hasNext()) {
				Reference ref = it.next();
				if (ref.getReferenceType().isFlow()) {
					return true;
				}
			}
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
	public boolean hasReferencesFrom(Address fromAddr) {
		lock.acquire();
		try {
			long addr = addrMap.getKey(fromAddr, false);
			if (addr == AddressMap.INVALID_ADDRESS_KEY) {
				return false;
			}
			RefList refList = fromCache.get(addr);
			if (refList != null && !refList.isEmpty()) {
				return true;
			}
			return fromAdapter.hasRefFrom(addr);
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
	public boolean hasReferencesFrom(Address fromAddr, int opIndex) {
		lock.acquire();
		try {
			RefList fromRefs = getFromRefs(fromAddr);
			if (fromRefs == null) {
				return false;
			}
			ReferenceIterator it = fromRefs.getRefs();
			while (it.hasNext()) {
				Reference ref = it.next();
				if (ref.getOperandIndex() == opIndex) {
					return true;
				}
			}
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
	public boolean hasReferencesTo(Address toAddr) {
		if (toAddr.isStackAddress() || toAddr.isRegisterAddress()) {
			throw new UnsupportedOperationException(
				"hasReferencesTo not supported for stack/register addresses");
		}
		lock.acquire();
		try {
			long addr = addrMap.getKey(toAddr, false);
			if (addr == AddressMap.INVALID_ADDRESS_KEY) {
				return false;
			}
			RefList refList = toCache.get(addr);
			if (refList != null && !refList.isEmpty()) {
				return true;
			}
			return toAdapter.hasRefTo(addr);
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
	public void removeAllReferencesFrom(Address beginAddr, Address endAddr) {
		try {
			AddressIterator it =
				fromAdapter.getFromIterator(new AddressSet(beginAddr, endAddr), true);

			while (it.hasNext()) {
				Address addr = it.next();
				removeAllFrom(addr);
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
	}

	@Override
	public void removeAllReferencesFrom(Address fromAddr) {
		try {
			removeAllFrom(fromAddr);
		}
		catch (IOException e) {
			program.dbError(e);
		}

	}

	void removeReference(Address fromAddr, Address toAddr, int opIndex) {
		lock.acquire();
		try {
			Reference ref = null;
			RefList fromRefs = getFromRefs(fromAddr);
			if (fromRefs != null) {
				ref = fromRefs.getRef(toAddr, opIndex);
				if (ref != null) {
					fromRefs.removeRef(toAddr, opIndex);
					if (fromRefs.isEmpty()) {
						fromCache.delete(fromRefs.getKey());
					}
				}
			}
			RefList toRefs = getToRefs(toAddr);
			if (toRefs != null) {
				if (ref == null) {
					ref = toRefs.getRef(fromAddr, opIndex);
				}
				toRefs.removeRef(fromAddr, opIndex);
				if (toRefs.isEmpty()) {
					toCache.delete(toRefs.getKey());
				}
			}
			if (ref != null) {
				referenceRemoved(ref);
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Symbol is about to be removed
	 * @param symbol the symbol that will be removed
	 */
	public void symbolRemoved(Symbol symbol) {
		if (symbol.isDynamic()) {
			return;
		}
		if (symbol.getSymbolType() != SymbolType.LABEL) {
			checkFunctionChange(symbol);
			return;
		}
		long symID = symbol.getID();
		Address refAddr = symbol.getAddress();

		ReferenceIterator iter = getReferencesTo(refAddr);
		ArrayList<Reference> list = new ArrayList<>();
		while (iter.hasNext()) {
			Reference ref = iter.next();
			if (symID == ref.getSymbolID()) {
				list.add(ref);
			}
		}
		for (Reference ref : list) {
			removeAssociation(ref);
		}
	}

	/**
	 * Symbol has been added
	 * @param sym new symbol
	 */
	public void symbolAdded(Symbol sym) {
		checkFunctionChange(sym);
	}

	private void checkFunctionChange(Symbol sym) {
		SymbolType symbolType = sym.getSymbolType();
		if (symbolType == SymbolType.FUNCTION || symbolType == SymbolType.PARAMETER ||
			symbolType == SymbolType.LOCAL_VAR) {
			functionCacher.clearCache();
		}
	}

	@Override
	public void setAssociation(Symbol s, Reference ref) {
		if (s.getSymbolType() != SymbolType.LABEL || s.isDynamic()) {
			return;
		}
		lock.acquire();
		try {
			if (s instanceof VariableSymbolDB) {
				VariableStorage storage = ((VariableSymbolDB) s).getVariableStorage();
				if (!storage.contains(ref.getToAddress())) {
					throw new IllegalArgumentException("Variable symbol " + s.getName() +
						" does not contain referenced address: " + ref.getToAddress() + ")");
				}
			}
			else {
				Address symAddr = s.getAddress();
				if (!symAddr.equals(ref.getToAddress())) {
					throw new IllegalArgumentException("Symbol address(" + symAddr +
						") not equal to reference's To address(" + ref.getToAddress() + ")");
				}
			}
			try {
				setSymbolID(ref, s.getID());
			}
			catch (IOException e) {
				program.dbError(e);
			}
			program.setObjChanged(ChangeManager.DOCR_SYMBOL_ASSOCIATION_ADDED, ref.getFromAddress(),
				ref, null, s);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void removeAssociation(Reference ref) {
		lock.acquire();
		try {
			setSymbolID(ref, -1);
			program.setObjChanged(ChangeManager.DOCR_SYMBOL_ASSOCIATION_REMOVED,
				ref.getFromAddress(), ref, null, null);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Reference updateRefType(Reference ref, RefType refType) {
		lock.acquire();
		try {
			if (ref.getReferenceType() == refType) {
				return ref;
			}
			RefList fromRefs = getFromRefs(ref.getFromAddress());
			if (fromRefs == null) {
				return null;
			}
			Address toAddr = ref.getToAddress();
			Reference curRef = fromRefs.getRef(toAddr, ref.getOperandIndex());
			if (curRef == null) {
				return null;
			}
			fromRefs.updateRefType(toAddr, ref.getOperandIndex(), refType);
			RefList toRefs = getToRefs(toAddr);
			if (toRefs != null) { // cope with buggy situation
				toRefs.updateRefType(ref.getFromAddress(), ref.getOperandIndex(), refType);
			}
			Reference newRef = fromRefs.getRef(toAddr, ref.getOperandIndex());
			referenceTypeChanged(newRef, curRef.getReferenceType(), refType);
			return newRef;
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
	public ReferenceIterator getReferencesTo(Address addr) {
		lock.acquire();
		try {
			if (addr.isStackAddress() || addr.isRegisterAddress()) {
				throw new UnsupportedOperationException(
					"getReferencesTo not supported for stack/register addresses");
			}
			RefList toRefs = getToRefs(addr);
			if (toRefs != null) {
				return toRefs.getRefs();
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return new EmptyMemReferenceIterator();
	}

	@Override
	public void invalidateCache(boolean all) {
		lock.acquire();
		try {
			fromCache.invalidate();
			toCache.invalidate();
			functionCacher.clearCache();
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Move all references to the specified oldAddr.  Any symbol binding will be discarded since
	 * these are intended for memory label references only.
	 * This method is intended specifically to support upgrading of certain references
	 * (i.e., Stack, Register and External addresses).
	 * NOTE! After ProgramDB version 12, this method will no longer be useful for
	 * upgrading stack and register references since they will not exist
	 * within the ReferenceTo-list.
	 * @param oldToAddr old reference to address
	 * @param newToAddr new reference to address
	 * @param monitor the monitor
	 * @return number of references updated
	 * @throws CancelledException if the task is cancelled 
	 * @throws IOException if a database exception occurs 
	 */
	public int moveReferencesTo(Address oldToAddr, Address newToAddr, TaskMonitor monitor)
			throws CancelledException, IOException {
		RefList toRefs = getToRefs(oldToAddr);
		if (toRefs == null) {
			return 0;
		}

		Reference[] refs = toRefs.getAllRefs();

		RefList newToRefs = null;
		if (!newToAddr.isStackAddress() && !newToAddr.isRegisterAddress()) {
			newToRefs = getToRefs(newToAddr);
			if (newToRefs == null) {
				newToRefs = toAdapter.createRefList(program, toCache, newToAddr);
			}
			newToRefs = newToRefs.checkRefListSize(toCache, refs.length);
		}

		for (Reference ref : refs) {
			monitor.checkCanceled();

			Address fromAddr = ref.getFromAddress();
			int opIndex = ref.getOperandIndex();

			RefList fromRefs = getFromRefs(fromAddr);
			if (fromRefs != null) {
				fromRefs.removeRef(oldToAddr, ref.getOperandIndex());
				fromRefs.addRef(fromAddr, newToAddr, ref.getReferenceType(), opIndex, -1,
					ref.isPrimary(), ref.getSource(), false, false, 0);
			}

			if (newToRefs != null) {
				newToRefs.addRef(fromAddr, newToAddr, ref.getReferenceType(), opIndex, -1,
					ref.isPrimary(), ref.getSource(), false, false, 0);
			}

		}

		toRefs.removeAll();
		toCache.delete(toRefs.getKey());

		return refs.length;
	}

	@Override
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor) {
		removeAllReferencesFrom(startAddr, endAddr);
	}

	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		lock.acquire();
		try {

			// Move all non-default references from the moved range.
			// All default references from the range will be removed.

			Address fromEndAddr = fromAddr.add(length - 1);

			// processing direction depends upon shift direction in case of overlap
			boolean forward = fromAddr.compareTo(toAddr) > 0;
			Address firstAddr = forward ? fromAddr : fromEndAddr;

			AddressIterator refSourceIter = getReferenceSourceIterator(firstAddr, forward);
			while (refSourceIter.hasNext()) {
				monitor.checkCanceled();

				Address oldFromAddr = refSourceIter.next();
				if ((forward && oldFromAddr.compareTo(fromEndAddr) > 0) ||
					(!forward && oldFromAddr.compareTo(fromAddr) < 0)) {
					break;
				}

				RefList fromRefs = getFromRefs(oldFromAddr);
				if (fromRefs == null) {
					continue;
				}

				Reference[] refs = fromRefs.getAllRefs();
// TODO: could attempt to reassign from refList address to improve performance
// would need to do handle corresponding to list fix-ups individually
				fromRefs.removeAll();
				fromCache.delete(fromRefs.getKey());

				long offset = oldFromAddr.subtract(fromAddr);
				Address newRefFromAddr = toAddr.add(offset);

				for (Reference ref : refs) {
					monitor.checkCanceled();

					Address newRefToAddr = ref.getToAddress();
					int opIndex = ref.getOperandIndex();
					RefList toRefs = getToRefs(newRefToAddr);

					if (newRefToAddr.compareTo(fromAddr) >= 0 &&
						newRefToAddr.compareTo(fromEndAddr) <= 0) {
						offset = newRefToAddr.subtract(fromAddr);
						newRefToAddr = toAddr.add(offset);
					}

					if (toRefs != null) {
						toRefs.removeRef(oldFromAddr, ref.getOperandIndex());
					}

					if (ref.getSource() != SourceType.DEFAULT) {

						long offsetOrShift = 0;
						if (ref instanceof OffsetReference) {
							offsetOrShift = ((OffsetReference) ref).getOffset();
						}
						if (ref instanceof ShiftedReference) {
							offsetOrShift = ((ShiftedReference) ref).getShift();
						}

						Reference newRef = addRef(newRefFromAddr, newRefToAddr,
							ref.getReferenceType(), ref.getSource(), opIndex,
							ref.isOffsetReference(), ref.isShiftedReference(), offsetOrShift);

						long symbolId = ref.getSymbolID();
						if (symbolId != -1) {
							setSymbolID(newRef, symbolId);
						}
					}
				}
			}

		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Returns the reference level for the references to the given address
	 * @param toAddr the address at which to find the highest reference level
	 */
	@Override
	public byte getReferenceLevel(Address toAddr) {

		try {
			DBRecord rec = toAdapter.getRecord(addrMap.getKey(toAddr, false));
			if (rec != null) {
				return rec.getByteValue(ToAdapter.REF_LEVEL_COL);
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return SymbolUtilities.UNK_LEVEL;
	}

	/*
	 * Get address iterator over references that are external entry memory references
	 */
	public AddressIterator getExternalEntryIterator() {
		lock.acquire();
		try {
			RefList refList = getFromRefs(Address.EXT_FROM_ADDRESS);
			if (refList != null) {
				return new ExtEntryAddressIterator(refList.getRefs());
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return new EmptyAddressIterator();
	}

	/**
	 * Return whether the address is an external entry point
	 * @param toAddr the address to test for external entry point
	 * @return true if the address is an external entry point
	 */
	public boolean isExternalEntryPoint(Address toAddr) {
		lock.acquire();
		try {
			RefList refList = getToRefs(toAddr);
			if (refList != null) {
				return refList.getRef(Address.EXT_FROM_ADDRESS, CodeUnit.MNEMONIC) != null;
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return false;
	}

	/**
	 * Create a memory reference to the given address to mark it as
	 * an external entry point.
	 * @param toAddr the address at which to make an external entry point
	 */
	public void addExternalEntryPointRef(Address toAddr) {
		if (!toAddr.isMemoryAddress()) {
			throw new IllegalArgumentException("Entry point address must be memory address");
		}
		if (!isExternalEntryPoint(toAddr)) {
			try {
				addRef(Address.EXT_FROM_ADDRESS, toAddr, RefType.EXTERNAL_REF, SourceType.DEFAULT,
					CodeUnit.MNEMONIC, false, false, 0);
			}
			catch (IOException e) {
				program.dbError(e);
			}
			externalEntryPointAdded(toAddr);
		}
	}

	/**
	 * Removes the external entry point at the given address
	 * @param addr that address at which to remove the external entry point attribute.
	 */
	public void removeExternalEntryPoint(Address addr) {
		if (isExternalEntryPoint(addr)) {
			removeReference(Address.EXT_FROM_ADDRESS, addr, CodeUnit.MNEMONIC);
			externalEntryPointRemoved(addr);
		}
	}

	private void externalEntryPointAdded(Address addr) {
		program.setChanged(ChangeManager.DOCR_EXTERNAL_ENTRY_POINT_ADDED, addr, addr, null, null);
	}

	private void externalEntryPointRemoved(Address addr) {
		program.setChanged(ChangeManager.DOCR_EXTERNAL_ENTRY_POINT_REMOVED, addr, addr, null, null);
	}

	private RefList getFromRefs(Address from) {
		lock.acquire();
		try {
			long fromAddr = addrMap.getKey(from, false);
			RefList refList = fromCache.get(fromAddr);
			if (refList == null) {
				try {
					refList = fromAdapter.getRefList(program, fromCache, from, fromAddr);
				}
				catch (IOException e) {
					dbError(e);
				}
			}
			return refList;
		}
		finally {
			lock.release();
		}
	}

	private RefList getToRefs(Address to) {
		lock.acquire();
		try {
			long toAddr = addrMap.getKey(to, false);
			RefList refList = toCache.get(toAddr);
			if (refList == null) {
				try {
					refList = toAdapter.getRefList(program, toCache, to, toAddr);
				}
				catch (ClosedException e) {
					// TODO this seems wrong here; no other method handles closed exceptions
				}
				catch (IOException e) {
					dbError(e);
				}
			}
			return refList;
		}
		finally {
			lock.release();
		}
	}

	/*
	 * Remove all references that have the "From" address as the given address.
	 */
	void removeAllFrom(Address fromAddr) throws IOException {
		lock.acquire();
		try {
			RefList fromRefs = getFromRefs(fromAddr);
			if (fromRefs == null) {
				return;
			}
			Reference[] refs = fromRefs.getAllRefs();
			for (Reference ref : refs) {
				RefList toRefs = getToRefs(ref.getToAddress());
				if (toRefs != null) { // cope with buggy situation
					toRefs.removeRef(fromAddr, ref.getOperandIndex());
					if (toRefs.isEmpty()) {
						toCache.delete(toRefs.getKey());
					}
				}
				referenceRemoved(ref);
			}
			fromRefs.removeAll();
			fromCache.delete(fromRefs.getKey());
		}
		finally {
			lock.release();
		}
	}

	private void removeAllFrom(Address fromAddr, int opIndex) {
		Reference[] refs = getReferences(fromAddr, opIndex);
		for (Reference ref : refs) {
			delete(ref);
		}
	}

	void setSymbolID(Reference ref, long symbolID) throws IOException {
		lock.acquire();
		try {
			RefList fromRefs = getFromRefs(ref.getFromAddress());
			if (fromRefs == null) {
				return;
			}
			Reference curRef = fromRefs.getRef(ref.getToAddress(), ref.getOperandIndex());
			if (curRef == null) {
				return;
			}
			fromRefs.setSymbolID(curRef, symbolID);

			RefList toRefs = getToRefs(ref.getToAddress());
			if (toRefs != null) {
				toRefs.setSymbolID(curRef, symbolID);
			}
		}
		finally {
			lock.release();
		}
	}

	private void referenceAdded(Reference ref) {
		Address addr = ref.getFromAddress();
		if (addr == Address.EXT_FROM_ADDRESS) {
			addr = null;
		}
		functionCacher.clearCache();
		program.setObjChanged(ChangeManager.DOCR_MEM_REFERENCE_ADDED, addr, ref, null, ref);
		if (ref.getReferenceType() == RefType.FALL_THROUGH) {
			program.getCodeManager().fallThroughChanged(ref.getFromAddress(), ref);
		}
	}

	private void referenceRemoved(Reference ref) {
		functionCacher.clearCache();
		program.setObjChanged(ChangeManager.DOCR_MEM_REFERENCE_REMOVED, ref.getFromAddress(), ref,
			ref, null);
		if (ref.getReferenceType() == RefType.FALL_THROUGH) {
			program.getCodeManager().fallThroughChanged(ref.getFromAddress(), null);
		}
	}

	private void referenceTypeChanged(Reference ref, RefType oldType, RefType newType) {
		functionCacher.clearCache();
		program.setObjChanged(ChangeManager.DOCR_MEM_REF_TYPE_CHANGED, ref.getFromAddress(), ref,
			oldType, newType);
		if (oldType == RefType.FALL_THROUGH) {
			program.getCodeManager().fallThroughChanged(ref.getFromAddress(), null);
		}
	}

	private void referencePrimaryChanged(Reference ref) {
		if (ref.isPrimary()) {
			program.setObjChanged(ChangeManager.DOCR_MEM_REF_PRIMARY_SET, ref.getFromAddress(), ref,
				null, ref);
		}
		else {
			program.setObjChanged(ChangeManager.DOCR_MEM_REF_PRIMARY_REMOVED, ref.getFromAddress(),
				ref, ref, null);
		}
	}

	class FromRefIterator implements ReferenceIterator {

		AddressIterator fromIter;
		ReferenceIterator refIter;

		/**
		 * Construct a reference iterator sorted on the from address.
		 * @param startFromAddr the first from address
		 */
		FromRefIterator(Address startFromAddr) {
			fromIter = getReferenceSourceIterator(startFromAddr, true);
		}

		/**
		 * Construct a reference iterator sorted on the from address.
		 * @param set set of from addresses
		 */
		FromRefIterator(AddressSetView set) {
			fromIter = getReferenceSourceIterator(set, true);
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean hasNext() {
			try {
				if (refIter != null && refIter.hasNext()) {
					return true;
				}
				Address fromAddr = fromIter.next();
				refIter = null;
				// Looping handles possibility of concurrent modification
				while (fromAddr != null && refIter == null) {
					RefList refList = getFromRefs(fromAddr);
					if (refList != null) {
						refIter = refList.getRefs();
					}
					else {
						fromAddr = fromIter.next();
					}
				}
			}
			catch (IOException e) {
				program.dbError(e);
			}
			return (refIter != null);
		}

		@Override
		public Reference next() {
			if (hasNext()) {
				return refIter.next();
			}
			return null;
		}

		@Override
		public Iterator<Reference> iterator() {
			return this;
		}
	}

	private class ExtEntryAddressIterator implements AddressIterator {

		private ReferenceIterator iter;
		private Address currentAddress;

		ExtEntryAddressIterator(ReferenceIterator iter) {
			this.iter = iter;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean hasNext() {
			findNext();
			return currentAddress != null;
		}

		@Override
		public Address next() {
			findNext();
			if (currentAddress != null) {
				Address addr = currentAddress;
				currentAddress = null;
				return addr;
			}
			return null;
		}

		private void findNext() {
			if (currentAddress == null) {
				while (iter.hasNext()) {
					Reference ref = iter.next();
					if (ref != null) {
						if (ref.isEntryPointReference()) {
							currentAddress = ref.getToAddress();
							break;
						}
					}
				}
			}
		}

		@Override
		public Iterator<Address> iterator() {
			return this;
		}
	}

	@Override
	public void dbError(IOException e) {
		program.dbError(e);
	}

	@Override
	public void delete(Reference ref) {
		removeReference(ref.getFromAddress(), ref.getToAddress(), ref.getOperandIndex());
	}

	@Override
	public ReferenceIterator getExternalReferences() {
		AddressSet set = new AddressSet(AddressSpace.EXTERNAL_SPACE.getMinAddress(),
			AddressSpace.EXTERNAL_SPACE.getMaxAddress());
		AddressIterator it = getReferenceDestinationIterator(set, true);
		return new ExternalReferenceIterator(it);
	}

	@Override
	public Reference addReference(Reference ref) {
		Address from = ref.getFromAddress();
		Address to = ref.getToAddress();
		RefType type = ref.getReferenceType();
		SourceType sourceType = ref.getSource();

		int opIndex = ref.getOperandIndex();
		if (ref.isExternalReference()) {
			ExternalLocation extLoc = ((ExternalReference) ref).getExternalLocation();
			try {
				return addExternalReference(from, extLoc.getParentNameSpace(), extLoc.getLabel(),
					extLoc.getAddress(), sourceType, opIndex, type);
			}
			catch (DuplicateNameException e) {
				throw new AssertException(e);
			}
			catch (InvalidInputException e) {
				throw new AssertException(e);
			}
		}
		if (ref.getToAddress().isStackAddress()) {
			return addStackReference(ref.getFromAddress(), opIndex,
				(int) ref.getToAddress().getOffset(), type, sourceType);
		}
		Reference memRef;
		if (ref.isOffsetReference()) {
			OffsetReference offRef = (OffsetReference) ref;
			memRef = addOffsetMemReference(from, to, offRef.getOffset(), type, sourceType, opIndex);
		}
		else if (ref.isShiftedReference()) {
			ShiftedReference shiftRef = (ShiftedReference) ref;
			memRef =
				addShiftedMemReference(from, to, shiftRef.getShift(), type, sourceType, opIndex);
		}
		else {
			memRef = addMemoryReference(from, to, type, sourceType, opIndex);
		}

		boolean isPrimary = ref.isPrimary();
		if (isPrimary != memRef.isPrimary()) {
			setPrimary(memRef, isPrimary);
		}
		return memRef;
	}

	@Override
	public Reference[] getReferencesFrom(Address fromAddr, int opIndex) {
		Reference[] retRefs = null;
		try {
			RefList fromRefs = getFromRefs(fromAddr);
			if (fromRefs == null) {
				return NO_REFS;
			}
			Reference[] refs = fromRefs.getAllRefs();
			int cnt = 0;
			for (Reference ref : refs) {
				if (ref.getOperandIndex() == opIndex) {
					cnt++;
				}
			}
			if (cnt == refs.length) {
				return refs;
			}
			retRefs = new Reference[cnt];
			cnt = 0;
			for (Reference ref : refs) {
				if (ref.getOperandIndex() == opIndex) {
					retRefs[cnt++] = ref;
				}
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		return retRefs;
	}

	class ExternalReferenceIterator implements ReferenceIterator {
		private AddressIterator it;
		private ReferenceIterator refIt;

		ExternalReferenceIterator(AddressIterator it) {
			this.it = it;
		}

		@Override
		public boolean hasNext() {
			return (refIt != null && refIt.hasNext()) || it.hasNext();
		}

		@Override
		public Reference next() {
			if (refIt == null || !refIt.hasNext()) {
				Address addr = it.next();
				if (addr != null) {
					refIt = getReferencesTo(addr);
				}

			}
			if (refIt != null) {
				return refIt.next();
			}
			return null;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public Iterator<Reference> iterator() {
			return this;
		}
	}

	ProgramDB getProgram() {
		return program;
	}

	private class FunctionVariableReferenceCacher {

		private Function cachedFunction;
		private SortedMap<Address, List<Reference>> references;
		private Map<Address, List<Variable>> variablesByAddress;

		synchronized void setFunction(Function function) {
			if (cachedFunction == function) {
				return;
			}

			clearCache();
			cachedFunction = function;
		}

		synchronized void clearCache() {
			cachedFunction = null;
			references = null;
		}

		synchronized SortedMap<Address, List<Reference>> getFunctionDataReferences() {

			if (references != null) {
				return references;
			}

			references = getSortedVariableReferences(cachedFunction);
			return references;
		}

		synchronized List<Variable> getVariables(Address address) {

			if (variablesByAddress != null) {
				return variablesByAddress.get(address);
			}

			Map<Address, List<Variable>> map =
				LazyMap.lazyMap(new HashMap<>(), () -> new ArrayList<>());

			for (Symbol s : symbolMgr.getSymbols(cachedFunction.getID())) {
				if (!s.getAddress().equals(address)) {
					continue;
				}
				Variable v = (Variable) s.getObject();
				map.get(address).add(v);
			}

			variablesByAddress = map;
			return variablesByAddress.get(address);
		}

		private SortedMap<Address, List<Reference>> getSortedVariableReferences(Function function) {
			SortedMap<Address, List<Reference>> newReferencesList =
				LazySortedMap.lazySortedMap(new TreeMap<>(), () -> new ArrayList<>());

			ReferenceIterator refIter = new FromRefIterator(function.getBody());
			while (refIter.hasNext()) {
				Reference ref = refIter.next();
				RefType referenceType = ref.getReferenceType();
				if (referenceType.isFlow() && !referenceType.isIndirect()) {
					continue;
				}

				Address toAddr = ref.getToAddress();
				newReferencesList.get(toAddr).add(ref);
			}
			return newReferencesList;
		}
	}

	private class Scope {

		int outOfScopeOffset;
		int firstUseOffset;

		Scope(int firstUseOffset, int outOfScopeOffset) {
			this.firstUseOffset = firstUseOffset;
			this.outOfScopeOffset = outOfScopeOffset;
		}

		int getFirstUseOffset() {
			return firstUseOffset;
		}

		int getOutOfScopeOffset() {
			return outOfScopeOffset;
		}
	}
}
