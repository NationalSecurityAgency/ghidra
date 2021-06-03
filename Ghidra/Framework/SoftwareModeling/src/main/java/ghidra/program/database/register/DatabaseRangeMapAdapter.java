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

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.util.AddressRangeMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.util.LanguageTranslator;
import ghidra.program.util.RangeMapAdapter;
import ghidra.util.Lock;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class DatabaseRangeMapAdapter implements RangeMapAdapter {

	static final String NAME_PREFIX = "Register_";
	static final String CONTEXT_TABLE_PREFIX =
		AddressRangeMapDB.RANGE_MAP_TABLE_PREFIX + NAME_PREFIX;

	private String mapName;
	private ErrorHandler errorHandler;
	private DBHandle dbh;
	private AddressRangeMapDB rangeMap;
	private AddressMap addressMap;

	public DatabaseRangeMapAdapter(Register register, DBHandle dbHandle, AddressMap addrMap,
			Lock lock, ErrorHandler errorHandler) {
		this.dbh = dbHandle;
		this.errorHandler = errorHandler;
		mapName = NAME_PREFIX + register.getName();
		rangeMap = new AddressRangeMapDB(dbHandle, addrMap, lock, mapName, errorHandler,
			BinaryField.INSTANCE, false);
		addressMap = addrMap;
	}

	/**
	 * @see ghidra.program.util.RangeMapAdapter#getAddressRangeIterator(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public AddressRangeIterator getAddressRangeIterator(Address startAddr, Address endAddr) {
		return rangeMap.getAddressRanges(startAddr, endAddr);
	}

	/**
	 * @see ghidra.program.util.RangeMapAdapter#getAddressRangeIterator()
	 */
	@Override
	public AddressRangeIterator getAddressRangeIterator() {
		return rangeMap.getAddressRanges();
	}

	/**
	 * @see ghidra.program.util.RangeMapAdapter#getValueRangeContaining(ghidra.program.model.address.Address)
	 */
	@Override
	public AddressRange getValueRangeContaining(Address addr) {
		return rangeMap.getAddressRangeContaining(addr);
	}

	/**
	 * @see ghidra.program.util.RangeMapAdapter#getValue(ghidra.program.model.address.Address)
	 */
	@Override
	public byte[] getValue(Address address) {
		BinaryField field = (BinaryField) rangeMap.getValue(address);
		if (field != null) {
			return field.getBinaryData();
		}
		return null;
	}

	/**
	 * @see ghidra.program.util.RangeMapAdapter#moveAddressRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address, long, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		rangeMap.moveAddressRange(fromAddr, toAddr, length, monitor);
	}

	/**
	 * @see ghidra.program.util.RangeMapAdapter#set(ghidra.program.model.address.Address, ghidra.program.model.address.Address, byte[])
	 */
	@Override
	public void set(Address start, Address end, byte[] bytes) {
		Field field = new BinaryField(bytes);
		rangeMap.paintRange(start, end, field);
	}

	/**
	 * @see ghidra.program.util.RangeMapAdapter#clearRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public void clearRange(Address start, Address end) {
		rangeMap.clearRange(start, end);
	}

	/**
	 * @see ghidra.program.util.RangeMapAdapter#clearAll()
	 */
	@Override
	public void clearAll() {
		rangeMap.dispose();
	}

	@Override
	public boolean isEmpty() {
		return rangeMap.isEmpty();
	}

	/**
	 * @see ghidra.program.util.RangeMapAdapter#setLanguage(ghidra.program.util.LanguageTranslator, ghidra.program.model.lang.Register, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void setLanguage(LanguageTranslator translator, Register mapReg, TaskMonitor monitor)
			throws CancelledException {

		Register newReg = translator.getNewRegister(mapReg);
		if (newReg == null) {
			// register not translated - clear map
			rangeMap.dispose();
			rangeMap = null;
			return;
		}
		Register newBaseReg = newReg.getBaseRegister();

		AddressRangeMapDB tempMap = null;
		if (!newReg.isBaseRegister() || translator.isValueTranslationRequired(mapReg)) {

			// Create temporary map
			String tempName = "TEMP_MAP";
			int retry = 0;
			while (AddressRangeMapDB.exists(dbh, tempName)) {
				tempName = "TEMP_MAP" + (++retry);
			}
			tempMap = new AddressRangeMapDB(dbh, addressMap, new Lock("Test"), tempName,
				errorHandler, BinaryField.INSTANCE, false);

			// Translate range map data into tempMap
			monitor.initialize(rangeMap.getRecordCount());
			monitor.setMessage("Converting " + mapReg.getName() + " values...");
			int cnt = 0;
			AddressRangeIterator rangeIter = rangeMap.getAddressRanges();
			while (rangeIter.hasNext()) {
				if (monitor.isCancelled()) {
					tempMap.dispose();
					throw new CancelledException();
				}
				AddressRange range = rangeIter.next();
				BinaryField value = (BinaryField) rangeMap.getValue(range.getMinAddress());
				byte[] oldBytes = value.getBinaryData();
				RegisterValue regValue = new RegisterValue(mapReg, oldBytes);
				regValue = translator.getNewRegisterValue(regValue);
				if (regValue != null && regValue.hasAnyValue()) {
					byte[] newBytes = regValue.toBytes();
					tempMap.paintRange(range.getMinAddress(), range.getMaxAddress(),
						new BinaryField(newBytes));
				}
				monitor.setProgress(++cnt);
			}
		}

		String newMapName = NAME_PREFIX + newBaseReg.getName();
		if (tempMap == null) {
			if (mapName.equals(newMapName)) {
				// Nothing to change
				return;
			}
		}
		else {
			rangeMap.dispose();
			rangeMap = tempMap;
		}
		if (rangeMap != null) {
			try {
				rangeMap.setName(newMapName);
			}
			catch (DuplicateNameException e) {
				throw new AssertException("Unexpected DuplicateNameException");
			}
		}
		mapName = newMapName;
	}

	@Override
	public void checkWritableState() {
		try {
			dbh.checkTransaction();
		}
		catch (NoTransactionException e) {
			throw new IllegalStateException(e.getMessage(), e);
		}
	}

}
