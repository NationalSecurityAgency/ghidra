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
import ghidra.util.datastruct.IndexRangeIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public interface RangeMapAdapter {

	/**
	 * Returns the byte array that has been associated with the given index.
	 * @param address the address at which to retrieve a byte array.
	 * @return the byte array that has been associated with the given index or null if no such
	 * association exists.
	 */
	byte[] getValue(Address address);

	/**
	 * Move all values within an address range to a new range.
	 * @param fromAddr the first address of the range to be moved.
	 * @param toAddr the address where to the range is to be moved.
	 * @param length the number of addresses to move.
	 * @param monitor the task monitor.
	 * @throws CancelledException if the user canceled the operation via the task monitor.
	 */
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException;

	/**
	 * Associates the given byte array with all indexes in the given range.  Any existing values
	 * will be over written.
	 * @param start the first address in the range.
	 * @param end the last Address(inclusive) in the range.
	 * @param bytes the bytes to associate with the range.
	 */
	void set(Address start, Address end, byte[] bytes);

	/**
	 * Returns an {@link IndexRangeIterator} over all stored values in the given range.  If the
	 * given range intersects an actual stored range either at the beginning or end, the iterator
	 * will return those ranges truncated to fit within the given range.
	 * @param start the first Address in the range.
	 * @param end the last Address (inclusive) index in the range.
	 * @return an {@link IndexRangeIterator} over all stored values.
	 */
	AddressRangeIterator getAddressRangeIterator(Address start, Address end);

	/**
	 * Returns an {@link IndexRangeIterator} over all stored values.
	 * @return an {@link IndexRangeIterator} over all stored values.
	 */
	AddressRangeIterator getAddressRangeIterator();

	/**
	 * Clears all associated values in the given range.
	 * @param start the first address in the range to clear.
	 * @param end the end address in the range to clear.
	 */
	void clearRange(Address start, Address end);

	/**
	 * Clears all values.
	 */
	void clearAll();

	/**
	 * Returns true if this storage has no associated values for any address
	 * @return true if this storage has no associated values for any address
	 */
	boolean isEmpty();

	/**
	 * Update table name and values to reflect new base register
	 * @param translator
	 * @param mapReg
	 * @param monitor
	 * @throws CancelledException
	 */
	void setLanguage(LanguageTranslator translator, Register mapReg, TaskMonitor monitor)
			throws CancelledException;

	/**
	 * Returns the bounding address-range containing addr and the the same value throughout.
	 * This range will be limited by any value change associated with the base register.
	 * @param addr the containing address
	 * @return single value address-range containing addr
	 */
	public AddressRange getValueRangeContaining(Address addr);

	/**
	 * Verify that adapter is in a writable state (i.e., valid transaction has been started).
	 * @throws IllegalStateException if not in a writable state
	 */
	public void checkWritableState();

}
