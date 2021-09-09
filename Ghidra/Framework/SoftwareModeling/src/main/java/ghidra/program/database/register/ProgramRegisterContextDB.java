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
package ghidra.program.database.register;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.ManagerDB;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.code.CodeManager;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.util.AddressRangeMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.util.*;
import ghidra.util.Lock;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class ProgramRegisterContextDB extends AbstractStoredProgramContext implements ManagerDB {

	private DBHandle dbHandle;
	private ErrorHandler errorHandler;
	private Lock lock;
	private ProgramDB program;
	private AddressMap addrMap;

	private boolean changing = false;

	public ProgramRegisterContextDB(DBHandle dbHandle, ErrorHandler errHandler, Language lang,
			CompilerSpec compilerSpec, AddressMap addrMap, Lock lock, int openMode,
			CodeManager codeMgr, TaskMonitor monitor) throws VersionException, CancelledException {
		super(lang);
		this.addrMap = addrMap;
		this.dbHandle = dbHandle;
		this.errorHandler = errHandler;
		this.lock = lock;

		boolean oldContextDataExists = OldProgramContextDB.oldContextDataExists(dbHandle);
		boolean upgrade = oldContextDataExists && !contextDataExists(dbHandle);
		if (openMode != DBConstants.UPGRADE && upgrade) {
			throw new VersionException(true);
		}

		registerValueMap = new HashMap<>();
		defaultRegisterValueMap = new HashMap<>();
		initializeDefaultValues(lang, compilerSpec);
		initializedCurrentValues();

		if (upgrade) {
			upgrade(addrMap, monitor);
		}

		if (openMode == DBConstants.UPGRADE && oldContextDataExists) {
			try {
				OldProgramContextDB.removeOldContextData(dbHandle);
			}
			catch (IOException e) {
				errorHandler.dbError(e);
			}
		}
	}

	private static boolean contextDataExists(DBHandle dbh) {
		for (Table table : dbh.getTables()) {
			if (table.getName().startsWith(DatabaseRangeMapAdapter.CONTEXT_TABLE_PREFIX)) {
				return true;
			}
		}
		return false;
	}

	private void upgrade(AddressMap addressMapExt, TaskMonitor monitor) throws CancelledException {

		OldProgramContextDB oldContext =
			new OldProgramContextDB(dbHandle, errorHandler, language, addressMapExt, lock);

		for (Register register : language.getRegisters()) {
			if (register.getBaseRegister() != register) {
				continue;
			}
			AddressRangeIterator it = oldContext.getRegisterValueAddressRanges(register);
			while (it.hasNext()) {
				monitor.checkCanceled();
				AddressRange range = it.next();
				RegisterValue regValue =
					oldContext.getNonDefaultValue(register, range.getMinAddress());
				recoverOldRegisterValue(range.getMinAddress(), range.getMaxAddress(), regValue);
			}
		}
	}

	private void recoverOldRegisterValue(Address start, Address end, RegisterValue value) {

		Register reg = value.getRegister();

		if (reg.isProcessorContext()) {
			if (!reg.hasChildren()) {
				return; // no context fields defined
			}
			byte[] validBitMask = reg.getBaseMask();
			Arrays.fill(validBitMask, (byte) 0);
			for (Register child : reg.getChildRegisters()) {
				byte[] mask = child.getBaseMask();
				for (int i = 0; i < validBitMask.length; i++) {
					validBitMask[i] |= mask[i];
				}
			}
			byte[] maskValue = value.toBytes();
			for (int i = 0; i < validBitMask.length; i++) {
				maskValue[i] &= validBitMask[i];
				maskValue[i + validBitMask.length] &= validBitMask[i];
			}
			value = new RegisterValue(reg, maskValue);
		}

		try {
			setRegisterValue(start, end, value);
		}
		catch (ContextChangeException e) {
			throw new AssertException("Unexpected context error during upgrade", e);
		}
	}

	private void initializedCurrentValues() {
		String tableNamePrefix =
			AddressRangeMapDB.RANGE_MAP_TABLE_PREFIX + DatabaseRangeMapAdapter.NAME_PREFIX;

		Table[] tables = dbHandle.getTables();
		for (Table table : tables) {
			if (table.getName().startsWith(tableNamePrefix)) {
				String registerName = table.getName().substring(tableNamePrefix.length());
				Register register = getRegister(registerName);
				if (register != null) {
					RangeMapAdapter adapter = new DatabaseRangeMapAdapter(register, dbHandle,
						addrMap, lock, errorHandler);
					createRegisterValueStore(register, adapter);
				}
			}
		}
	}

	/**
	 * Intialize context with default values defined by pspec and cspec.
	 * NOTE: cspec values take precedence
	 * @param lang processor language
	 * @param compilerSpec compiler specification
	 */
	public void initializeDefaultValues(Language lang, CompilerSpec compilerSpec) {
		defaultRegisterValueMap.clear();
		lang.applyContextSettings(this);
		if (compilerSpec != null) {
			compilerSpec.applyContextSettings(this);
		}
	}

	@Override
	public void invalidateCache(boolean all) throws IOException {
		this.invalidateReadCache();
	}

	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		super.moveAddressRange(fromAddr, toAddr, length, monitor);
	}

	@Override
	public void programReady(int openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
	}

	@Override
	public void setProgram(ProgramDB program) {
		this.program = program;
	}

	@Override
	protected RangeMapAdapter createNewRangeMapAdapter(Register baseRegister) {
		return new DatabaseRangeMapAdapter(baseRegister, dbHandle, addrMap, lock, errorHandler);
	}

	private void checkContextWrite(Register reg, Address start, Address end)
			throws ContextChangeException {
		if (changing || !reg.getBaseRegister().equals(getBaseContextRegister())) {
			return;
		}
		CodeManager codeManager = program.getCodeManager();
		codeManager.checkContextWrite(start, end);
	}

	@Override
	public void deleteAddressRange(Address start, Address end, TaskMonitor monitor) {
		lock.acquire();
		try {
			super.deleteAddressRange(start, end, monitor);
			if (program != null) {
				program.setRegisterValuesChanged(null, start, end);
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void remove(Address start, Address end, Register register)
			throws ContextChangeException {
		lock.acquire();
		boolean restore = false;
		try {
			checkContextWrite(register, start, end);
			restore = !changing; // indicates that we just initiated a change
			changing = true;
			super.remove(start, end, register);
			if (program != null) {
				program.setRegisterValuesChanged(register, start, end);
			}
		}
		finally {
			if (restore) {
				changing = false;
			}
			lock.release();
		}
	}

	@Override
	public void setValue(Register register, Address start, Address end, BigInteger value)
			throws ContextChangeException {
		lock.acquire();
		boolean restore = false;
		try {
			checkContextWrite(register, start, end);
			restore = !changing; // indicates that we just initiated a change
			changing = true;
			super.setValue(register, start, end, value);
			if (program != null) {
				program.setRegisterValuesChanged(register, start, end);
			}
		}
		finally {
			if (restore) {
				changing = false;
			}
			lock.release();
		}

	}

	@Override
	public void setRegisterValue(Address start, Address end, RegisterValue value)
			throws ContextChangeException {
		lock.acquire();
		boolean restore = false;
		try {
			// FIXME: We do not properly handle painting context across the full 
			// address space which should be avoided.  A non-zero image
			// base offset can result in a improperly coalesced long key-range.
			checkContextWrite(value.getRegister(), start, end);
			restore = !changing; // indicates that we just initiated a change
			changing = true;
			super.setRegisterValue(start, end, value);
			if (program != null) {
				program.setRegisterValuesChanged(value.getRegister(), start, end);
			}
		}
		finally {
			if (restore) {
				changing = false;
			}
			lock.release();
		}
	}

	/**
	 * Perform context upgrade due to a language change
	 * @param translator language translator required by major upgrades (may be null)
	 * @param newCompilerSpec new compiler specification
	 * @param programMemory program memory
	 * @param monitor task monitor
	 * @throws CancelledException thrown if monitor cancelled
	 */
	public void setLanguage(LanguageTranslator translator, CompilerSpec newCompilerSpec,
			AddressSetView programMemory, TaskMonitor monitor) throws CancelledException {

		if (translator == null) {
			// Language instance unchanged
			boolean clearContext = Boolean.valueOf(
				language.getProperty(GhidraLanguagePropertyKeys.RESET_CONTEXT_ON_UPGRADE));
			if (clearContext) {
				RegisterValueStore store = registerValueMap.get(baseContextRegister);
				if (store != null) {
					store.clearAll();
				}
			}
			initializeDefaultValues(language, newCompilerSpec);
			return;
		}

		Language newLanguage = translator.getNewLanguage();

		// Sort the registers by size so that largest come first.
		// This prevents the remove call below from incorrectly clearing 
		// smaller registers that are part of a larger register.
		List<Register> registers = new ArrayList<Register>(language.getRegisters());
		Collections.sort(registers, (r1, r2) -> r2.getBitLength() - r1.getBitLength());

		// Map all register stores to new registers
		for (Register register : registers) {
			monitor.checkCanceled();
			if (!register.isBaseRegister()) {
				continue; // only consider non-context base registers
			}
			RegisterValueStore store = registerValueMap.get(register);
			if (store == null) {
				continue;
			}

			boolean clearContext = register.isProcessorContext() && Boolean.valueOf(
				newLanguage.getProperty(GhidraLanguagePropertyKeys.RESET_CONTEXT_ON_UPGRADE));

			// Update storage range map
			if (clearContext || !store.setLanguage(translator, monitor)) {
				// Clear and remove old register value store
				Msg.warn(this,
					"WARNING! Discarding all context for register " + register.getName());
				store.clearAll();
			}
			registerValueMap.remove(register);
		}

		init(newLanguage);

		initializeDefaultValues(newLanguage, newCompilerSpec);

		registerValueMap.clear();
		initializedCurrentValues();

		// May need to fill-in blank context areas with a new specified context value 
		Register ctxReg = newLanguage.getContextBaseRegister();
		if (ctxReg != Register.NO_CONTEXT && translator.isValueTranslationRequired(ctxReg)) {
			RegisterValue gapValue = new RegisterValue(ctxReg);
			gapValue = translator.getNewRegisterValue(gapValue);
			if (gapValue != null && gapValue.hasAnyValue()) {
				fillInContextGaps(ctxReg, gapValue, programMemory);
			}
		}
	}

	private void fillInContextGaps(Register ctxReg, RegisterValue gapValue,
			AddressSetView programMemory) {

		AddressSet area = new AddressSet(programMemory);

		RegisterValueStore store = registerValueMap.get(ctxReg);
		if (store != null) {
			AddressRangeIterator addressRangeIterator = store.getAddressRangeIterator();
			while (addressRangeIterator.hasNext()) {
				area.delete(addressRangeIterator.next());
			}
		}
		AddressRangeIterator addressRanges = area.getAddressRanges();
		while (addressRanges.hasNext()) {
			AddressRange range = addressRanges.next();
			try {
				setRegisterValue(range.getMinAddress(), range.getMaxAddress(), gapValue);
			}
			catch (ContextChangeException e) {
				throw new AssertException("Unexpected context error during language upgrade", e);
			}
		}

	}

	@Override
	public void flushProcessorContextWriteCache() {
		lock.acquire();
		try {
			super.flushProcessorContextWriteCache();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void invalidateProcessorContextWriteCache() {
		lock.acquire();
		try {
			super.invalidateProcessorContextWriteCache();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressRangeIterator getRegisterValueAddressRanges(Register register) {
		lock.acquire();
		try {
			return super.getRegisterValueAddressRanges(register);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressRange getRegisterValueRangeContaining(Register register, Address addr) {
		lock.acquire();
		try {
			return super.getRegisterValueRangeContaining(register, addr);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressRangeIterator getRegisterValueAddressRanges(Register register, Address start,
			Address end) {
		lock.acquire();
		try {
			return super.getRegisterValueAddressRanges(register, start, end);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressRangeIterator getDefaultRegisterValueAddressRanges(Register register) {
		lock.acquire();
		try {
			return super.getDefaultRegisterValueAddressRanges(register);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressRangeIterator getDefaultRegisterValueAddressRanges(Register register,
			Address start, Address end) {
		lock.acquire();
		try {
			return super.getDefaultRegisterValueAddressRanges(register, start, end);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Register[] getRegistersWithValues() {
		lock.acquire();
		try {
			return super.getRegistersWithValues();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean hasValueOverRange(Register reg, BigInteger value, AddressSetView addrSet) {
		lock.acquire();
		try {
			return super.hasValueOverRange(reg, value, addrSet);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setDefaultValue(RegisterValue registerValue, Address start, Address end) {
		lock.acquire();
		try {
			super.setDefaultValue(registerValue, start, end);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public RegisterValue getDefaultValue(Register register, Address address) {
		lock.acquire();
		try {
			return super.getDefaultValue(register, address);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public RegisterValue getNonDefaultValue(Register register, Address address) {
		lock.acquire();
		try {
			return super.getNonDefaultValue(register, address);
		}
		finally {
			lock.release();
		}
	}

}
