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
package ghidra.program.util;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * This is a generalized class for storing register values over ranges.  The values include mask bits
 * to indicate which bits within the register are being set.  The mask is stored along with the
 * value so the getValue method can indicate back which bits in the value are valid.  If existing
 * values already exist at an address, the values are combined according to the masks.  Any new value
 * bits that have their associated mask bits on will overwrite any existing bits and the new mask will
 * be anded to the existing mask.  Other bits will not be affected.
 * 
 * This class takes a RangeMapAdapter that will adapt to some lower level storage.  There are current
 * two implementations - one that uses an ObjectRangeMap for storing register values in memory and
 * the other that uses RangeMapDB for storing register values in the database.
 * 
 */

public class RegisterValueStore {

	private Register baseRegister;
	private RangeMapAdapter rangeMap;

	//
	// Write Cache Limitations:
	// The write cache consists of a single memory range which is intended to reduce
	// database IO overhead during code block disassembly.  The cache will be flushed automatically
	// if an iterator is invoked or context changes which do not qualify as an extension
	// to the current write range.  At the time this was written a single threaded disassembly
	// was supported, use of multiple DisassemblerContexts concurrently for the same context
	// storage (i.e., Program) will cause the cache to flush much more frequently and will
	// greatly reduce efficiency.  The cache must be flushed externally prior to closing the
	// current database transaction. 
	//
	private boolean rangeWriteCacheEnabled = false;
	private RegisterValue rangeWriteCacheValue;
	private Address rangeWriteCacheMin;
	private Address rangeWriteCacheMax;

	/**
	 * Constructs a new RegisterValueStore. 
	 * @param rangeMap the rangeMapAdapter that handles the low level storage of byte arrays
	 */
	public RegisterValueStore(Register register, RangeMapAdapter rangeMap,
			boolean enableRangeWriteCache) {
		this.baseRegister = register.getBaseRegister();
		this.rangeMap = rangeMap;
		rangeWriteCacheEnabled = enableRangeWriteCache;
	}

	void flushWriteCache() {
		if (rangeWriteCacheValue == null) {
			return;
		}
		doSetValue(rangeWriteCacheMin, rangeWriteCacheMax, rangeWriteCacheValue);
		rangeWriteCacheValue = null;
	}

	void invalidateWriteCache() {
		rangeWriteCacheValue = null;
	}

	/**
	 * Move all register values within an address range to a new range.
	 * @param fromAddr the first address of the range to be moved.
	 * @param toAddr the address where to the range is to be moved.
	 * @param length the number of addresses to move.
	 * @param monitor the task monitor.
	 * @throws CancelledException if the user canceled the operation via the task monitor.
	 */
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		flushWriteCache();
		rangeMap.moveAddressRange(fromAddr, toAddr, length, monitor);
	}

	/**
	 * Sets the given register value (contains value and mask) across the given address range.  Any
	 * existing values in the range that have values that are not part of the input mask are 
	 * not changed. 
	 * @param start the start of the range to set the register value. 
	 * @param end the end of the range(inclusive) to set the register value.
	 * @param newValue the new register value to set.
	 */
	public void setValue(Address start, Address end, RegisterValue newValue) {

		if (rangeWriteCacheEnabled) {
			if (rangeWriteCacheValue != null) {
				try {
					Address nextAddrInRange = rangeWriteCacheMax.addNoWrap(1);
					if (start.equals(nextAddrInRange) && newValue.equals(rangeWriteCacheValue)) {
						rangeWriteCacheMax = end;
						return;
					}
				}
				catch (AddressOverflowException e) {
					// assume we were at end of space
				}
				flushWriteCache();
			}
			else {
				// Ensure that transaction is open to avoid delayed error condition
				rangeMap.checkWritableState();
			}
			rangeWriteCacheValue = newValue;
			rangeWriteCacheMin = start;
			rangeWriteCacheMax = end;
			return;
		}

		doSetValue(start, end, newValue);
	}

	private void doSetValue(Address start, Address end, RegisterValue newValue) {
		if (!start.hasSameAddressSpace(end)) {
			throw new IllegalArgumentException(
				"Start and end addresses must be in the same address space.");
		}

		// if newValue corresponds to base and all bits are to be changed - no need to merge
		if (newValue.getRegister().isBaseRegister() && newValue.hasValue()) {
			rangeMap.set(start, end, newValue.toBytes());
			return;
		}

		// Otherwise, combine bytes where values already exist.
		List<AddressRange> list = new ArrayList<AddressRange>();
		AddressRangeIterator rangeIt = rangeMap.getAddressRangeIterator(start, end);
		while (rangeIt.hasNext()) {
			list.add(rangeIt.next());
		}
		Iterator<AddressRange> it = list.iterator();
		while (it.hasNext()) {
			AddressRange indexRange = it.next();
			Address rangeStart = indexRange.getMinAddress();
			Address rangeEnd = indexRange.getMaxAddress();
			if (rangeStart.compareTo(start) > 0) {
				rangeMap.set(start, rangeStart.previous(), newValue.toBytes());
			}
			byte[] currentBytes = rangeMap.getValue(rangeStart);
			RegisterValue currentValue = new RegisterValue(baseRegister, currentBytes);
			RegisterValue combinedValue = currentValue.combineValues(newValue);
			rangeMap.set(rangeStart, rangeEnd, combinedValue.toBytes());
			try {
				start = rangeEnd.addNoWrap(1);
			}
			catch (AddressOverflowException e) {
				return;
			}
		}
		if (start != null && start.compareTo(end) <= 0) {
			rangeMap.set(start, end, newValue.toBytes());
		}
	}

	/**
	 * Delete all stored values and free/delete underlying storage.
	 */
	public void clearAll() {
		rangeWriteCacheValue = null;
		rangeMap.clearAll();
	}

	/**
	 * Clears the address range of any set bits using the mask from the given register value.
	 * existing values in the range that have values that are not part of the input mask are 
	 * not changed. If register is null, just clear all the values in range
	 * @param start the start of the range to clear the register value bits. 
	 * @param end the end of the range(inclusive) to clear the register value bits.
	 * @param register the register whos mask to use.  If null, clear all values in the given range.
	 */
	public void clearValue(Address start, Address end, Register register) {

		flushWriteCache();

		// if the mask is all on, then just clear any values that are stored in this range
		if (register == null || register.isBaseRegister()) {
			rangeMap.clearRange(start, end);
			return;
		}

		// Otherwise, mask off bits according to the mask passed in.
		List<AddressRange> list = new ArrayList<AddressRange>();
		AddressRangeIterator rangeIt = rangeMap.getAddressRangeIterator(start, end);
		while (rangeIt.hasNext()) {
			list.add(rangeIt.next());
		}
		Iterator<AddressRange> it = list.iterator();
		while (it.hasNext()) {
			AddressRange indexRange = it.next();
			Address rangeStart = indexRange.getMinAddress();
			Address rangeEnd = indexRange.getMaxAddress();

			byte[] mask = register.getBaseMask();

			RegisterValue currentBaseValue =
				new RegisterValue(register.getBaseRegister(), rangeMap.getValue(rangeStart));
			RegisterValue newBaseValue = currentBaseValue.clearBitValues(mask);

			if (!newBaseValue.hasAnyValue()) {
				rangeMap.clearRange(rangeStart, rangeEnd);
			}
			else {
				rangeMap.set(rangeStart, rangeEnd, newBaseValue.toBytes());
			}
			start = rangeEnd.next();
		}
	}

	/**
	 * Returns the RegisterValue (value and mask) associated with the given address. 
	 * @param address the address at which to get the RegisterValue.
	 * @return the RegisterValue 
	 */
	public RegisterValue getValue(Register register, Address address) {

		if (rangeWriteCacheValue != null && address.compareTo(rangeWriteCacheMin) >= 0 &&
			address.compareTo(rangeWriteCacheMax) <= 0) {
			return rangeWriteCacheValue.getRegisterValue(register);
		}

		byte[] bytes = rangeMap.getValue(address);
		if (bytes == null) {
			return null;
		}
		return new RegisterValue(register, bytes);
	}

	/**
	 * Returns an AddressRangeIterator that will return address ranges everywhere that register values
	 * have been set within the given range.
	 * @param startAddress the start address to get stored register values.
	 * @param endAddress the end address to get stored register values.
	 * @return an AddressRangeIterator that will return address ranges everywhere that register
	 * values have been set within the given range.
	 */
	public AddressRangeIterator getAddressRangeIterator(Address startAddress, Address endAddress) {

		// Assume we must be in open transaction if range cache is active
		flushWriteCache();

		return rangeMap.getAddressRangeIterator(startAddress, endAddress);
	}

	/**
	 * Returns an AddressRangeIterator that will return address ranges everywhere that register
	 * values have been set.
	 * @return an AddressRangeIterator that will return address ranges everywhere that register
	 * values have been set.
	 */
	public AddressRangeIterator getAddressRangeIterator() {

		// Assume we must be in open transaction if range cache is active
		flushWriteCache();

		return rangeMap.getAddressRangeIterator();
	}

	/**
	 * Returns true if this store has no associated values for any address.
	 * @return  true if this store has no associated values for any address.
	 */
	public boolean isEmpty() {
		return rangeWriteCacheValue == null && rangeMap.isEmpty();
	}

	/**
	 * Preserve register values and handle register name/size change.
	 * @param translator
	 * @param monitor
	 * @return true if translated successfully, false if register not mapped 
	 * value storage should be discarded.
	 * @throws CancelledException
	 */
	public boolean setLanguage(LanguageTranslator translator, TaskMonitor monitor)
			throws CancelledException {
		Register newReg = translator.getNewRegister(baseRegister);
		if (newReg == null) {
			return false;
		}
		flushWriteCache();
// TODO: What should we do if new register is not a base-register ? - The code below will not work!
		if (newReg.isProcessorContext() || !newReg.isBaseRegister() ||
			!newReg.getName().equals(baseRegister.getName()) ||
			newReg.getBitLength() != baseRegister.getBitLength()) {
			rangeMap.setLanguage(translator, baseRegister, monitor);
			baseRegister = newReg.getBaseRegister();
		}
		return true;
	}

	/**
	 * Returns the bounding address-range containing addr and the the same value throughout.
	 * This range will be limited by any value change associated with the base register.
	 * @param addr the contained address
	 * @return single value address-range containing addr
	 */
	public AddressRange getValueRangeContaining(Address addr) {

		// Assume we must be in open transaction if range cache is active
		flushWriteCache();

		return rangeMap.getValueRangeContaining(addr);
	}

}
