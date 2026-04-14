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

import db.DBRecord;
import ghidra.program.database.external.ExternalManagerDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.*;
import ghidra.program.util.LabelFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Lock.Closeable;

/**
 * Symbols that represent "labels" or external data locations
 */
public class CodeSymbol extends MemorySymbol {

	/**
	 * Constructs a new CodeSymbol
	 * @param mgr the symbol manager
	 * @param addr the address associated with the symbol
	 * @param record the record for this symbol
	 * @param key the database id to use as the object's database key
	 */
	CodeSymbol(SymbolManager mgr, Address addr, DBRecord record, long key) {
		super(mgr, addr, record, key);
	}

	@Override
	public SymbolType getSymbolType() {
		return SymbolType.LABEL;
	}

	@Override
	protected boolean refresh(DBRecord rec) {
		if (!isDynamic()) {
			return super.refresh(rec);
		}
		if (rec != null) {
			return false;// dynamic symbols do not have a record
		}
		address = symbolMgr.getDynamicAddress(key);
		return symbolMgr.hasDynamicSymbol(address);
	}

	@Override
	public boolean delete() {
		boolean keepReferences = !isExternal();
		return delete(keepReferences);
	}

	/**
	 * Delete code/label symbol
	 * @param keepReferences if false all references to this symbols address will be removed,
	 * otherwise associated references will simply be disassociated following symbol removal
	 * (see {@link SymbolManager#doRemoveSymbol(SymbolDB)}.
	 * @return true if symbol successfully removed
	 */
	public boolean delete(boolean keepReferences) {
		try (Closeable c = lock.write()) {
			if (!keepReferences) {
				symbolMgr.getReferenceManager().removeAllReferencesTo(getAddress());
			}
			return super.delete();
		}
	}

	@Override
	public Object getObject() {
		try (Closeable c = lock.read()) {
			if (!refreshIfNeeded()) {
				return null;
			}
			if (isExternal()) {
				return symbolMgr.getExternalManager().getExternalLocation(this);
			}
			CodeUnit cu = symbolMgr.getCodeManager().getCodeUnitContaining(address);
			if (cu != null) {
				if (address.equals(cu.getMinAddress())) {
					return cu;
				}
				if (cu instanceof Data) {
					Data data = (Data) cu;
					data = data.getPrimitiveAt((int) address.subtract(data.getMinAddress()));
					return data != null ? data : cu;
				}
			}
			return null;
		}
	}

	@Override
	public boolean isPrimary() {
		if (getSource() == SourceType.DEFAULT || isExternal()) {
			return true;
		}
		return doCheckIsPrimary();
	}

	@Override
	public boolean setPrimary() {
		try (Closeable c = lock.write()) {
			if (address.isExternalAddress()) { // can't set primary on external locations
				return false;
			}
			SymbolDB oldPrimarySymbol = null;
			checkDeleted();
			if (isPrimary()) {
				return false; // already primary
			}

			oldPrimarySymbol = (SymbolDB) symbolMgr.getPrimarySymbol(address);
			if (oldPrimarySymbol != null) {
				if (oldPrimarySymbol instanceof FunctionSymbol) {
					return false; // not allowed if function symbol exists at this address.
				}
				if (oldPrimarySymbol instanceof CodeSymbol) {
					((CodeSymbol) oldPrimarySymbol).setPrimary(false);
				}
			}

			setPrimary(true);
			symbolMgr.primarySymbolSet(this, oldPrimarySymbol);
			return true;
		}
	}

	void setPrimary(boolean primary) {
		doSetPrimary(primary);
	}

	@Override
	public ProgramLocation getProgramLocation() {
		return new LabelFieldLocation(this);
	}

	@Override
	public boolean isValidParent(Namespace parent) {
		return super.isValidParent(parent) &&
			SymbolType.LABEL.isValidParent(symbolMgr.getProgram(), parent, address, isExternal());
	}

	@Override
	protected String doGetName() {
		if (getSource() == SourceType.DEFAULT && isExternal()) {
			return ExternalManagerDB.getDefaultExternalName(this);
		}
		return super.doGetName();
	}

	@Override
	protected SourceType validateNameSource(String newName, SourceType source) {
		if (!isExternal()) {
			if (source == SourceType.DEFAULT) {
				return SourceType.ANALYSIS;
			}
			return source;
		}
		if (newName == null || newName.length() == 0 || SymbolUtilities
				.isReservedDynamicLabelName(newName, symbolMgr.getProgram().getAddressFactory())) {
			return SourceType.DEFAULT;
		}
		return source;
	}

	void setIsValid() {
		super.setValid();
	}
}
