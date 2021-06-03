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
package ghidra.program.database.util;

import java.io.IOException;

import db.*;
import ghidra.program.database.map.*;
import ghidra.program.model.address.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Collection of static functions for upgrading various database tables.
 */
public class DatabaseTableUtils {

	/**
	 * Updates an indexed address field for when a block is moved.
	 * @param table the database table
	 * @param addrCol the address column in the table
	 * @param addrMap the address map
	 * @param fromAddr the from address of the block being moved
	 * @param toAddr the address to where the block is being moved.
	 * @param length the size of the block being moved.
	 * @param monitor the task monitor
	 * @throws IOException thrown if a database io error occurs.
	 * @throws CancelledException thrown if the user cancels the move operation.
	 */
	public static void updateIndexedAddressField(Table table, int addrCol, AddressMap addrMap,
			Address fromAddr, Address toAddr, long length, RecordFilter filter, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (length <= 0) {
			throw new IllegalArgumentException("length must be > 0");
		}
		try {
			fromAddr.addNoWrap(length - 1);
			toAddr.addNoWrap(length - 1);
		}
		catch (AddressOverflowException e) {
			throw new IllegalArgumentException("Illegal range: end range overflow");
		}
		boolean startFromTop = fromAddr.compareTo(toAddr) > 0;
		DBFieldIterator it = new AddressIndexPrimaryKeyIterator(table, addrCol, addrMap,
			new AddressSet(fromAddr, fromAddr.add(length - 1)), startFromTop);
		while (startFromTop ? it.hasNext() : it.hasPrevious()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			Field key = startFromTop ? it.next() : it.previous();
			DBRecord rec = table.getRecord(key);
			if (filter == null || filter.matches(rec)) {
				Address addr = addrMap.decodeAddress(rec.getLongValue(addrCol));
				addr = toAddr.add(addr.subtract(fromAddr));
				rec.setLongValue(addrCol, addrMap.getKey(addr, true));
				table.putRecord(rec);
			}
		}
	}

	/**
	 * Handles redoing a table whose key is address based when a ranges of addresses is moved.
	 * @param table the database table.
	 * @param addrMap the address map.
	 * @param fromAddr the from address of the block being moved.
	 * @param toAddr the destination address of the block being moved.
	 * @param length the size of the block being moved.
	 * @param monitor the taskmonitor
	 * @throws IOException thrown if a database io error occurs.
	 * @throws CancelledException thrown if the user cancels the move operation.
	 */
	public static void updateAddressKey(Table table, AddressMap addrMap, Address fromAddr,
			Address toAddr, long length, TaskMonitor monitor)
			throws IOException, CancelledException {

		if (length <= 0) {
			throw new IllegalArgumentException("length must be > 0");
		}

		Address endAddr;
		try {
			endAddr = fromAddr.addNoWrap(length - 1);
		}
		catch (AddressOverflowException e) {
			throw new IllegalArgumentException("Illegal range: end range overflow");
		}

		updateAddressKey(table, addrMap, fromAddr, endAddr, toAddr, monitor);
	}

	/**
	 * Handles redoing a table whose key is address based when a ranges of addresses is moved.
	 * @param table the database table.
	 * @param addrMap the address map.
	 * @param fromAddr the first address of the block being moved.
	 * @param endAddr the last address of the block being moved.
	 * @param toAddr the destination address of the block being moved.
	 * @param monitor the task monitor
	 * @throws IOException thrown if a database io error occurs.
	 * @throws CancelledException thrown if the user cancels the move operation.
	 */
	public static void updateAddressKey(Table table, AddressMap addrMap, Address fromAddr,
			Address endAddr, Address toAddr, TaskMonitor monitor)
			throws IOException, CancelledException {

		long length = endAddr.subtract(fromAddr);
		if (length < 0) {
			throw new IllegalArgumentException("endAddr must be greater than fromAddr");
		}
		try {
			toAddr.addNoWrap(length);
		}
		catch (AddressOverflowException e) {
			throw new IllegalArgumentException("Illegal range: end range overflow");
		}

		DBHandle tmp = new DBHandle();
		try {
			tmp.startTransaction();

			Table tmpTable = tmp.createTable("tmp", table.getSchema());

			RecordIterator it =
				new AddressKeyRecordIterator(table, addrMap, fromAddr, endAddr, fromAddr, true);
			while (it.hasNext()) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				DBRecord rec = it.next();
				Address addr = addrMap.decodeAddress(rec.getKey());
				long offset = addr.subtract(fromAddr);
				addr = toAddr.add(offset);
				rec.setKey(addrMap.getKey(addr, true));
				tmpTable.putRecord(rec);
			}

			AddressRecordDeleter.deleteRecords(table, addrMap, fromAddr, endAddr);

			it = tmpTable.iterator();
			while (it.hasNext()) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				DBRecord rec = it.next();
				table.putRecord(rec);
			}
		}
		finally {
			tmp.close();
		}
	}

}
