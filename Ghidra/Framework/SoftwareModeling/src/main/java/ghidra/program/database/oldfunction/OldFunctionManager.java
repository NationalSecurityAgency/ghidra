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
package ghidra.program.database.oldfunction;

import java.io.IOException;
import java.util.Iterator;

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.DataTypeManagerDB;
import ghidra.program.database.function.FunctionDB;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * This class only exists to support upgrading Ghidra Version 2.1 and earlier.
 * <BR>
 * <b>NOTE: Programmers should not use this class!</b>
 */
public class OldFunctionManager implements ErrorHandler {

	private DBHandle dbHandle;
	private ErrorHandler errHandler;
	private OldFunctionMapDB functionMap;
	private OldFunctionDBAdapter functionAdapter;
	private OldStackVariableDBAdapter stackVarAdapter;
	private OldRegisterVariableDBAdapter registerAdapter;
	private ProgramDB program;
	private DataTypeManagerDB dataManager;
	private AddressMap addrMap;

	/**
	 * Constructs a new OldFunctionManager.
	 * @param dbHandle data base handle
	 * @param errHandler the error handler
	 * @param addrMap the address map
	 * @throws VersionException if function manager's version does not match its expected version
	 */
	public OldFunctionManager(DBHandle dbHandle, ErrorHandler errHandler, AddressMap addrMap)
			throws VersionException {
		this.dbHandle = dbHandle;
		this.errHandler = errHandler;
		this.addrMap = addrMap.getOldAddressMap();
		initializeAdapters();
	}

	/**
	 * Actually does the work of upgrading the old program function manager.
	 * @param upgradeProgram the program to upgrade
	 * @param monitor the task monitor to allow the user to cancel the upgrade
	 * @throws CancelledException if the user cancels the upgrade
	 * @throws IOException if an i/o error occurs
	 */
	public void upgrade(ProgramDB upgradeProgram, TaskMonitor monitor)
			throws CancelledException, IOException {

		if (this.program != null) {
			throw new AssertException("Function manager already upgraded");
		}
		this.program = upgradeProgram;
		dataManager = upgradeProgram.getDataTypeManager();

		monitor.setMessage("Upgrading Functions...");
		monitor.initialize(getFunctionCount());
		int cnt = 0;

		OldFunctionIteratorDB iter = getFunctions();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			upgradeFunction(iter.next());
			monitor.setProgress(++cnt);
		}
		dispose();
	}

	/**
	 * Copy old function into programs current function manager.
	 * @param function existing function
	 */
	private void upgradeFunction(OldFunctionDataDB oldFunc) {

		Address entryPt = oldFunc.getEntryPoint();
		SymbolTable symTable = program.getSymbolTable();
		Symbol s = symTable.getPrimarySymbol(entryPt);
		String baseName = null;
		if (s != null && s.getSource() != SourceType.DEFAULT) {
			baseName = s.getName();
			s.delete();
		}
		else {
			baseName = SymbolUtilities.getDefaultFunctionName(entryPt);
		}
		String name = baseName;
		FunctionDB func = null;
		try {
			func = (FunctionDB) program.getFunctionManager().createFunction(name, entryPt,
				oldFunc.getBody(), SourceType.USER_DEFINED);
			func.setCustomVariableStorage(true);
			func.setComment(oldFunc.getComment());
			func.setRepeatableComment(oldFunc.getRepeatableComment());
			func.setReturnType(oldFunc.getReturnType(), SourceType.ANALYSIS);

			func.setValidationEnabled(false); // limit use of compiler spec during upgrade

			func.setStackPurgeSize(oldFunc.getStackDepthChange());
			StackFrame oldFrame = oldFunc.getStackFrame();
			StackFrame frame = func.getStackFrame();
			frame.setLocalSize(oldFrame.getLocalSize());
			frame.setReturnAddressOffset(oldFrame.getReturnAddressOffset());

			// don't worry about parameter offset if bad, function will compute it.
//			try {
//				frame.setParameterOffset(oldFrame.getParameterOffset());
//			}
//			catch (IllegalArgumentException e) {
//			}

			Parameter[] oldParms = oldFunc.getParameters();
			for (Parameter var : oldParms) {
				if (var.getVariableStorage().isBadStorage()) {
					Msg.error(this, "Discarded invalid parameter (" + func.getName() + " at " +
						func.getEntryPoint() + ")");
					continue;
				}
				boolean done = false;
				while (!done) {
					try {
						func.addParameter(var, SourceType.USER_DEFINED);
						done = true;
					}
					catch (DuplicateNameException e) {
						try {
							var.setName(var.getName() + ".dup", SourceType.USER_DEFINED);
						}
						catch (DuplicateNameException e1) {
						}
					}
				}
			}

			Variable[] oldLocalVars = oldFrame.getLocals();
			for (Variable var : oldLocalVars) {
				boolean done = false;
				while (!done) {
					try {
						func.addLocalVariable(var, SourceType.USER_DEFINED);
						done = true;
					}
					catch (DuplicateNameException e) {
						try {
							var.setName(var.getName() + ".dup", SourceType.USER_DEFINED);
						}
						catch (DuplicateNameException e1) {
						}
					}
				}
			}
		}
		catch (OverlappingFunctionException e) {
			throw new AssertException(e);
		}
		catch (InvalidInputException e) {
			throw new AssertException(e);
		}
		finally {
			if (func != null) {
				func.setValidationEnabled(true);
			}
		}
	}

	private void initializeAdapters() throws VersionException {
		VersionException versionExc = null;
		try {
			functionAdapter = OldFunctionDBAdapter.getAdapter(dbHandle, addrMap);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			stackVarAdapter = OldStackVariableDBAdapter.getAdapter(dbHandle, addrMap);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			registerAdapter = OldRegisterVariableDBAdapter.getAdapter(dbHandle, addrMap);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		functionMap = new OldFunctionMapDB(dbHandle, this, addrMap);
		if (versionExc != null) {
			throw versionExc;
		}
	}

	ProgramDB getProgram() {
		return program;
	}

	OldFunctionDBAdapter getFunctionAdapter() {
		return functionAdapter;
	}

	OldRegisterVariableDBAdapter getRegisterVariableAdapter() {
		return registerAdapter;
	}

	OldStackVariableDBAdapter getStackVariableAdapter() {
		return stackVarAdapter;
	}

	DataType getDataType(long dataTypeId) {
		DataType dataType = dataManager.getDataType(dataTypeId);
		if (dataType == null || dataType.isDeleted()) {
			return DataType.DEFAULT;
		}
		if (dataType.getLength() > 0) {
			// Return variable - although it could be too big
			return dataType;
		}
		if (dataType instanceof Pointer) {
			return program.getDataTypeManager().getPointer(((Pointer) dataType).getDataType());
		}
		return program.getDataTypeManager().getPointer(dataType);
	}

	long getDataTypeId(DataType dataType) {
		return dataManager.getResolvedID(dataType);
	}

	int getFunctionCount() {
		return functionAdapter.getRecordCount();
	}

	AddressSetView getFunctionBody(long functionKey) {
		return functionMap.getBody(functionKey);
	}

	synchronized OldFunctionDataDB getFunction(DBRecord rec) {
		return new OldFunctionDataDB(this, addrMap, rec, null);
	}

	/**
	 * Get an iterator over functions
	 *
	 * @return an iterator over functions.
	 */
	synchronized OldFunctionIteratorDB getFunctions() {
		try {
			return new OldFunctionIteratorDB();
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return null;
	}

	/**
	 * @see db.util.ErrorHandler#dbError(java.io.IOException)
	 */
	@Override
	public void dbError(IOException e) {
		errHandler.dbError(e);
	}

	/**
	 * Function iterator class.
	 */
	private class OldFunctionIteratorDB implements Iterator<OldFunctionDataDB> {

		private RecordIterator recordIter;
		private OldFunctionDataDB func;
		private boolean hasNext = false;

		/**
		 * Construct a function iterator over all functions.
		 */
		OldFunctionIteratorDB() throws IOException {
			recordIter = functionAdapter.iterateFunctionRecords();
		}

		/**
		 * @see ghidra.program.model.listing.FunctionIterator#hasNext()
		 */
		@Override
		public boolean hasNext() {
			if (hasNext) {
				return true;
			}
			synchronized (OldFunctionManager.this) {
				try {
					DBRecord rec = recordIter.next();
					if (rec != null) {
						func = getFunction(rec);
						hasNext = true;
					}
				}
				catch (IOException e) {
					errHandler.dbError(e);
				}
				return hasNext;
			}
		}

		/**
		 * @see ghidra.program.model.listing.FunctionIterator#next()
		 */
		@Override
		public OldFunctionDataDB next() {
			if (hasNext || hasNext()) {
				hasNext = false;
				return func;
			}
			return null;
		}

		/**
		 * @see java.util.Iterator#remove()
		 */
		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * Permanently discards all data resources associated with the old function manager.
	 * This should be invoked when an upgrade of all function data has been completed.
	 * @throws IOException
	 */
	public synchronized void dispose() throws IOException {
		functionMap.dispose();
		functionAdapter.deleteTable(dbHandle);
		stackVarAdapter.deleteTable(dbHandle);
		registerAdapter.deleteTable(dbHandle);

		// Remove Function variable tables which were never employed
		dbHandle.deleteTable("Function Variables");
		dbHandle.deleteTable("Function Var Ranges");
	}

}
