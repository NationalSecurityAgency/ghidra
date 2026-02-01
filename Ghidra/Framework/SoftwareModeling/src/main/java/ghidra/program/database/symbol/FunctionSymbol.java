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
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.external.ExternalManagerDB;
import ghidra.program.database.function.FunctionManagerDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.*;
import ghidra.program.util.FunctionReturnTypeFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Symbol class for functions.
 */
public class FunctionSymbol extends MemorySymbol {

	private FunctionManagerDB functionMgr;

	/**
	 * Construct a new FunctionSymbol
	 * @param symbolMgr the symbol manager.
	 * @param cache symbol object cache
	 * @param address the address for this symbol.
	 * @param record the record for this symbol.
	 */
	public FunctionSymbol(SymbolManager symbolMgr, DBObjectCache<SymbolDB> cache, Address address,
			DBRecord record) {
		super(symbolMgr, cache, address, record);
		this.functionMgr = symbolMgr.getFunctionManager();
	}

	@Override
	public SymbolType getSymbolType() {
		return SymbolType.FUNCTION;
	}

	boolean isThunk() {
		return functionMgr.isThunk(key);
	}

	@Override
	public void setNameAndNamespace(String newName, Namespace newNamespace, SourceType source)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		lock.acquire();
		try {
			boolean namespaceChange = !getParentNamespace().equals(newNamespace);
			super.setNameAndNamespace(newName, newNamespace, source);
			if (namespaceChange) {
				functionMgr.functionNamespaceChanged(key);
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean delete() {
		lock.acquire();
		try {
			boolean restoreLabel = isExternal() || (getSource() != SourceType.DEFAULT);
			String symName = getName();
			Symbol parentSymbol = getParentSymbol();
			String extOrigImportName = null;
			Address extProgramAddr = null;
			if (isExternal()) {
				// preserve external data
				extOrigImportName = getExternalOriginalImportedName();
				extProgramAddr = getExternalProgramAddress();
			}
			Namespace namespace = getParentNamespace();
			SourceType source = getSource();
			boolean pinned = isPinned();
			if (getID() > 0) {
				symbolMgr.removeChildren(this);
			}

			if (!functionMgr.doRemoveFunction(key)) {
				return false;
			}

			if (super.delete()) {
				if ((parentSymbol instanceof SymbolDB) && ((SymbolDB) parentSymbol).isDeleting()) {
					// do not replace function with label if parent namespace is getting removed
					return false;
				}
				if (restoreLabel) {
					// Recreate a symbol with the function symbol's name because deleting the function 
					// does not mean that we want to lose the function name (that is our policy).
					Symbol newSymbol;
					if (isExternal()) {
						newSymbol = symbolMgr.createExternalCodeSymbol(address, symName, namespace,
							source, extOrigImportName, extProgramAddr);
					}
					else {
						newSymbol = symbolMgr.createLabel(address, symName, namespace, source);
						newSymbol.setPrimary();
						if (pinned) {
							newSymbol.setPinned(true);
						}
					}
					if (newSymbol == null && isExternal()) {
						// remove all associated external references if external symbol not restored
						symbolMgr.getReferenceManager().removeAllReferencesTo(getAddress());
					}
				}
				return true;
			}
		}
		catch (InvalidInputException e) {
			// This shouldn't happen.
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
		catch (IOException e) {
			symbolMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return false;
	}

	@Override
	public Function getObject() {
		return functionMgr.getFunction(key);
	}

	@Override
	public boolean isPrimary() {
		return true;
	}

	@Override
	public ProgramLocation getProgramLocation() {
		lock.acquire();
		try {
			if (!checkIsValid()) {
				return null;
			}
			Function f = getObject();
			String signature = f.getPrototypeString(false, false);
			return new FunctionReturnTypeFieldLocation(getProgram(), address, 0, signature,
				f.getReturnType().getName());
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean isValidParent(Namespace parent) {
		return super.isValidParent(parent) && SymbolType.FUNCTION
				.isValidParent(symbolMgr.getProgram(), parent, address, isExternal());
	}

	@Override
	protected String doGetName() {
		if (getSource() == SourceType.DEFAULT) {
			if (isExternal()) {
				return ExternalManagerDB.getDefaultExternalName(this);
			}

			// Check for thunk function
			Symbol thunkedSymbol = getThunkedSymbol();
			if (thunkedSymbol instanceof FunctionSymbol) {
				FunctionSymbol thunkedFuncSym = (FunctionSymbol) thunkedSymbol;
				String thunkName = thunkedFuncSym.getName();
				if (thunkedFuncSym.getSource() == SourceType.DEFAULT &&
					thunkedFuncSym.getThunkedSymbol() == null) {
					// if thunking a default non-thunk function
					thunkName = "thunk_" + thunkName;
				}
				return thunkName;
			}
			return SymbolUtilities.getDefaultFunctionName(address);
		}
		return super.doGetName();
	}

	@Override
	protected Namespace doGetParentNamespace() {

		// Check for default thunk function which should return the
		// parent namespace of the thunked-function
		if (getSource() == SourceType.DEFAULT) {
			Symbol thunkedSymbol = getThunkedSymbol();
			if (thunkedSymbol instanceof FunctionSymbol) {
				FunctionSymbol thunkedFuncSym = (FunctionSymbol) thunkedSymbol;
				return thunkedFuncSym.getParentNamespace();
			}
		}
		return super.doGetParentNamespace();
	}

	private Symbol getThunkedSymbol() {
		long thunkedFunctionId = functionMgr.getThunkedFunctionId(key);
		return (thunkedFunctionId >= 0) ? symbolMgr.getSymbol(thunkedFunctionId) : null;
	}

	@Override
	protected SourceType validateNameSource(String newName, SourceType source) {
//		if (isThunk()) {
//			return source; // unexpected - already handled
//		}
		if (newName == null || newName.length() == 0) {
			return SourceType.DEFAULT;
		}
		if (isExternal()) {
			if (SymbolUtilities.isReservedDynamicLabelName(newName,
				symbolMgr.getProgram().getAddressFactory())) {
				return SourceType.DEFAULT;
			}
		}
		else {
			String defaultName = SymbolUtilities.getDynamicName(SymbolUtilities.FUN_LEVEL, address);
			if (defaultName.equals(newName)) {
				return SourceType.DEFAULT;
			}
		}
		if (source == SourceType.DEFAULT) {
			source = SourceType.ANALYSIS;
		}
		return source;
	}

	@Override
	protected List<SymbolDB> getSymbolsDynamicallyRenamedByMyRename() {
		List<Long> thunkFunctionIds = functionMgr.getThunkFunctionIds(key);
		if (thunkFunctionIds == null) {
			return null;
		}
		List<SymbolDB> list = new ArrayList<>(thunkFunctionIds.size());
		for (long id : thunkFunctionIds) {
			SymbolDB s = (SymbolDB) symbolMgr.getSymbol(id);
			if (s != null && s.getSource() == SourceType.DEFAULT) {
				list.add(s);
			}
		}
		return list;
	}

	@Override
	public Reference[] getReferences(TaskMonitor monitor) {
		lock.acquire();
		try {
			checkIsValid();
			Reference[] refs = super.getReferences(monitor);
			if (monitor == null) {
				monitor = TaskMonitor.DUMMY;
			}
			if (monitor.isCancelled()) {
				return refs;
			}
			List<Long> thunkIds = functionMgr.getThunkFunctionIds(key);
			if (thunkIds == null) {
				return refs;
			}
			int thunkCnt = thunkIds.size();
			Reference[] newRefs = new Reference[refs.length + thunkCnt];
			System.arraycopy(refs, 0, newRefs, thunkCnt, refs.length);
			for (int i = 0; i < thunkCnt; i++) {
				if (monitor.isCancelled()) {
					return refs;
				}
				Symbol s = symbolMgr.getSymbol(thunkIds.get(i));
				newRefs[i] = new ThunkReference(s.getAddress(), getAddress());
				monitor.setProgress(refs.length + i);
			}
			return newRefs;
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
			int count = super.getReferenceCount();
			List<Long> thunkIds = functionMgr.getThunkFunctionIds(key);
			if (thunkIds != null) {
				count += thunkIds.size();
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
			if (super.hasReferences()) {
				return true;
			}
			List<Long> thunkIds = functionMgr.getThunkFunctionIds(key);
			return thunkIds != null ? (thunkIds.size() != 0) : false;
		}
		finally {
			lock.release();
		}
	}

}
