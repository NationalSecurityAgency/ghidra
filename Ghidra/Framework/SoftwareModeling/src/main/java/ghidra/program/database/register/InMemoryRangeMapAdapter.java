/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.util.LanguageTranslator;
import ghidra.program.util.RangeMapAdapter;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class InMemoryRangeMapAdapter implements RangeMapAdapter {
	private AddressRangeObjectMap<byte[]> rangeMap;

	public InMemoryRangeMapAdapter() {
		rangeMap = new AddressRangeObjectMap<byte[]>();
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
		rangeMap = new AddressRangeObjectMap<byte[]>();
	}

	/**
	 * @see ghidra.program.util.RangeMapAdapter#getValueRangeContaining(ghidra.program.model.address.Address)
	 */
	@Override
	public AddressRange getValueRangeContaining(Address addr) {
		return rangeMap.getAddressRangeContaining(addr);
	}

	/**
	 * @see ghidra.program.util.RangeMapAdapter#getAddressRangeIterator(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public AddressRangeIterator getAddressRangeIterator(Address start, Address end) {
		return rangeMap.getAddressRangeIterator(start, end);
	}

	/**
	 * @see ghidra.program.util.RangeMapAdapter#getAddressRangeIterator()
	 */
	@Override
	public AddressRangeIterator getAddressRangeIterator() {
		return rangeMap.getAddressRangeIterator();
	}

	/**
	 * @see ghidra.program.util.RangeMapAdapter#getValue(ghidra.program.model.address.Address)
	 */
	@Override
	public byte[] getValue(Address address) {
		return rangeMap.getObject(address);
	}

	/**
	 * @see ghidra.program.util.RangeMapAdapter#set(ghidra.program.model.address.Address, ghidra.program.model.address.Address, byte[])
	 */
	@Override
	public void set(Address start, Address end, byte[] bytes) {
		rangeMap.setObject(start, end, bytes);
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
	 * @see ghidra.program.util.RangeMapAdapter#isEmpty()
	 */
	@Override
	public boolean isEmpty() {
		return rangeMap.isEmpty();
	}

	@Override
	public void checkWritableState() {
		// always writable
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
			clearAll();
			return;
		}

		if (newReg.isBaseRegister() && !translator.isValueTranslationRequired(mapReg)) {
			return;
		}

		AddressRangeObjectMap<byte[]> newRangeMap = new AddressRangeObjectMap<byte[]>();
		AddressRangeIterator addressRangeIterator = rangeMap.getAddressRangeIterator();
		while (addressRangeIterator.hasNext()) {
			monitor.checkCanceled();
			AddressRange range = addressRangeIterator.next();
			byte[] oldBytes = rangeMap.getObject(range.getMinAddress());
			RegisterValue regValue = new RegisterValue(mapReg, oldBytes);
			regValue = translator.getNewRegisterValue(regValue);
			if (regValue == null || !regValue.hasAnyValue()) {
				continue; // remove value range
			}
			byte[] newBytes = regValue.toBytes();
			newRangeMap.setObject(range.getMinAddress(), range.getMaxAddress(), newBytes);
		}
		rangeMap = newRangeMap;
	}
}
