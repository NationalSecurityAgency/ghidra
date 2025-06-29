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

import java.util.ArrayList;
import java.util.Objects;

import db.DBRecord;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.external.ExternalLocationDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.UnknownProgressWrappingTaskMonitor;

/**
 * {@link MemorySymbol} corresponds to any symbol that resides at a memory location.
 * The corresponding address may be either a {@link Address#isMemoryAddress() memory address}
 * or a fake {@link Address#isExternalAddress() external address}.  While an external address is
 * not a memory address it corresponds to an {@link ExternalLocation} which may identify a 
 * specific memory address if known.
 */
public abstract class MemorySymbol extends SymbolDB {

	/**
	 * Constructs a new MemorySymbol which corresponds to the specified symbol record,
	 * @param mgr the symbol manager
	 * @param cache symbol object cache
	 * @param addr the address associated with the symbol
	 * @param record the record for this symbol
	 */
	protected MemorySymbol(SymbolManager mgr, DBObjectCache<SymbolDB> cache, Address addr,
			DBRecord record) {
		super(mgr, cache, addr, record);
		if (!addr.isMemoryAddress() && !isExternal()) {
			throw new IllegalArgumentException("memory or external address required");
		}
	}

	/**
	 * Constructs a new MemorySymbol which corresponds to the specified symbol key and has
	 * no record.  This is intended to support dynamic label cases which do not have a record
	 * and do not support an external address.
	 * @param mgr the symbol manager
	 * @param cache symbol object cache
	 * @param addr the address associated with the symbol
	 * @param key this must be the absolute encoding of addr
	 */
	protected MemorySymbol(SymbolManager mgr, DBObjectCache<SymbolDB> cache, Address addr,
			long key) {
		super(mgr, cache, addr, key);
		if (!addr.isMemoryAddress()) {
			throw new IllegalArgumentException("memory address required");
		}
	}

	@Override
	public final boolean isExternalEntryPoint() {
		validate(lock);
		return symbolMgr.isExternalEntryPoint(address);
	}

	@Override
	public final boolean isExternal() {
		return address.isExternalAddress();
	}

	@Override
	public final boolean isPinned() {
		if (!isExternal()) {
			return doIsPinned();
		}
		return false;
	}

	@Override
	public final void setPinned(boolean pinned) {
		if (!isExternal()) {
			doSetPinned(pinned);
		}
	}

	private boolean doIsPinned() {
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

	private void doSetPinned(boolean pinned) {
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
				record.setLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_ID_COL,
					newNamespace.getID());
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

	private boolean hasExactlyOneSymbolAtAddress(Address addr) {
		SymbolIterator it = symbolMgr.getSymbolsAsIterator(addr);
		if (!it.hasNext()) {
			return false;
		}
		it.next();
		return !it.hasNext();
	}

	@Override
	public int getReferenceCount() {
		lock.acquire();
		try {
			checkIsValid();
			ReferenceManager rm = symbolMgr.getReferenceManager();

			// If there is only one symbol, then all the references to this address count
			if (address.isExternalAddress() || hasExactlyOneSymbolAtAddress(address)) {
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

	/**
	 * Gets the optional field which is intended to store the original mangled name for an external
	 * {@link SymbolType#LABEL} or {@link SymbolType#FUNCTION} which has an 
	 * {@link Address#isExternalAddress() external address}.  These symbol types correspond 
	 * to {@link CodeSymbol} and {@link FunctionSymbol} DB symbol implementations respectively.
	 * This is generally set when an {@link ExternalLocationDB} is renamed which generally
	 * corresponds the external symbol being demangled.
	 * 
	 * @return original imported external name or null if not external or symbol has not been
	 * demangled or renamed.
	 */
	public final String getExternalOriginalImportedName() {
		lock.acquire();
		try {
			checkIsValid();
			if (record == null) {
				return null;
			}
			return record.getString(SymbolDatabaseAdapter.SYMBOL_ORIGINAL_IMPORTED_NAME_COL);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Sets the symbol's original imported external name field for an external 
	 * {@link SymbolType#LABEL} or {@link SymbolType#FUNCTION} which has an 
	 * {@link Address#isExternalAddress() external address}.  These symbol types correspond 
	 * to {@link CodeSymbol} and {@link FunctionSymbol} DB symbol implementations respectively.
	 * This is generally set when an {@link ExternalLocationDB} is renamed which generally
	 * corresponds the external symbol being demangled.
	 * 
	 * @param originalImportedName the original import name or null
	 * @param notify if true, a program change notification will be generated
	 * @throws UnsupportedOperationException if symbol is neither an external {@link SymbolType#LABEL}
	 * or {@link SymbolType#FUNCTION}.
	 */
	public final void setExternalOriginalImportedName(String originalImportedName, boolean notify) {
		SymbolType type = getSymbolType();
		if (!getAddress().isExternalAddress() ||
			(type != SymbolType.LABEL && type != SymbolType.FUNCTION)) {
			throw new javax.help.UnsupportedOperationException(
				"Symbol does not support: originalImportedName");
		}
		lock.acquire();
		try {
			checkDeleted();
			if (record == null) {
				return;
			}
			String oldData =
				record.getString(SymbolDatabaseAdapter.SYMBOL_ORIGINAL_IMPORTED_NAME_COL);
			if (!Objects.equals(originalImportedName, oldData)) {
				record.setString(SymbolDatabaseAdapter.SYMBOL_ORIGINAL_IMPORTED_NAME_COL,
					originalImportedName);
				updateRecord();
				if (notify) {
					symbolMgr.symbolDataChanged(this);
				}
			}
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Gets the optional field which is intended to store the original mangled name for an external
	 * {@link SymbolType#LABEL} or {@link SymbolType#FUNCTION} which has an 
	 * {@link Address#isExternalAddress() external address}.  These symbol types correspond 
	 * to {@link CodeSymbol} and {@link FunctionSymbol} DB symbol implementations respectively.
	 * This is generally set when an {@link ExternalLocationDB} is renamed which generally
	 * corresponds the external symbol being demangled.
	 * 
	 * @return external Program address or null if not external or unknown
	 */
	public final Address getExternalProgramAddress() {
		lock.acquire();
		try {
			checkIsValid();
			if (record == null) {
				return null;
			}

			// NOTE: String is used to avoid excessive AddressMap segmentation.  This does
			// prevent address space renaming as facilitated by Language upgrade and transition
			// capabilities.
			String addrStr = record.getString(SymbolDatabaseAdapter.SYMBOL_EXTERNAL_PROG_ADDR_COL);
			if (addrStr == null) {
				return null;
			}
			return symbolMgr.getAddressMap().getAddressFactory().getAddress(addrStr);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Sets the symbol's external Program Address field for an external 
	 * {@link SymbolType#LABEL} or {@link SymbolType#FUNCTION} which has an 
	 * {@link Address#isExternalAddress() external address}.  These symbol types correspond 
	 * to {@link CodeSymbol} and {@link FunctionSymbol} DB symbol implementations respectively.
	 * 
	 * @param externalProgramAddress the external Program Address which corresponds to the
	 * externally linked location (may be null).
	 * @param notify if true, a program change notification will be generated
	 * @throws UnsupportedOperationException if symbol is neither an external {@link SymbolType#LABEL}
	 * or {@link SymbolType#FUNCTION}.
	 */
	public final void setExternalProgramAddress(Address externalProgramAddress, boolean notify) {
		SymbolType type = getSymbolType();
		if (!getAddress().isExternalAddress() ||
			(type != SymbolType.LABEL && type != SymbolType.FUNCTION)) {
			throw new javax.help.UnsupportedOperationException(
				"Symbol does not support: external program address");
		}
		if (externalProgramAddress != null && !externalProgramAddress.isLoadedMemoryAddress()) {
			throw new IllegalArgumentException("Memory address required for external program");
		}
		lock.acquire();
		try {
			checkDeleted();
			if (record == null) {
				return;
			}
			String addrStr =
				externalProgramAddress != null ? externalProgramAddress.toString() : null;
			String oldData = record.getString(SymbolDatabaseAdapter.SYMBOL_EXTERNAL_PROG_ADDR_COL);
			if (!Objects.equals(addrStr, oldData)) {
				record.setString(SymbolDatabaseAdapter.SYMBOL_EXTERNAL_PROG_ADDR_COL, addrStr);
				updateRecord();
				if (notify) {
					symbolMgr.symbolDataChanged(this);
				}
			}
		}
		finally {
			lock.release();
		}
	}

	static void setExternalFields(DBRecord record, String originalImportName,
			Address externalProgramAddress) {
		String addrStr = externalProgramAddress != null ? externalProgramAddress.toString() : null;
		record.setString(SymbolDatabaseAdapter.SYMBOL_EXTERNAL_PROG_ADDR_COL, addrStr);
		record.setString(SymbolDatabaseAdapter.SYMBOL_ORIGINAL_IMPORTED_NAME_COL,
			originalImportName);
	}
}
