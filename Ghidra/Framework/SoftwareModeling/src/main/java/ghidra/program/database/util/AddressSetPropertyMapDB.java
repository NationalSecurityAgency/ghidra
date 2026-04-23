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

import java.util.ConcurrentModificationException;

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.util.ProgramEvent;
import ghidra.util.Lock;
import ghidra.util.Lock.Closeable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * AddressSetPropertyMap that uses a RangeMapDB to maintain a set of addresses.
 * 
 * 
 *
 */
public class AddressSetPropertyMapDB implements AddressSetPropertyMap {

	private static final String MY_PREFIX = "AddressSet - ";
	private static final String TABLE_PREFIX = AddressRangeMapDB.RANGE_MAP_TABLE_PREFIX + MY_PREFIX;

	private ProgramDB program;
	private AddressRangeMapDB propertyMap;
	private Lock lock;
	private boolean invalid;
	private String mapName;
	private static Field FIELD = new BooleanField(true);

	public static AddressSetPropertyMapDB getPropertyMap(ProgramDB program, String mapName,
			ErrorHandler errHandler, AddressMap addrMap, Lock lock) {

		try (Closeable c = lock.read()) {
			String tableName = AddressSetPropertyMapDB.TABLE_PREFIX + mapName;

			DBHandle dbh = program.getDBHandle();
			if (dbh.getTable(tableName) != null) {
				return new AddressSetPropertyMapDB(program, mapName, program, addrMap, lock);
			}
		}
		return null;
	}

	public static AddressSetPropertyMapDB createPropertyMap(ProgramDB program, String mapName,
			ErrorHandler errHandler, AddressMap addrMap, Lock lock) throws DuplicateNameException {
		try (Closeable c = lock.read()) {
			DBHandle dbh = program.getDBHandle();
			String tableName = AddressSetPropertyMapDB.TABLE_PREFIX + mapName;
			if (dbh.getTable(tableName) != null) {
				throw new DuplicateNameException(
					"Address Set Property Map named " + mapName + " already exists.");
			}

			return new AddressSetPropertyMapDB(program, mapName, program, addrMap, lock);
		}
	}

	private AddressSetPropertyMapDB(ProgramDB program, String mapName, ErrorHandler errHandler,
			AddressMap addrMap, Lock lock) {
		this.program = program;
		this.mapName = mapName;
		this.lock = lock;

		propertyMap = new AddressRangeMapDB(program.getDBHandle(), program.getAddressMap(),
			program.getLock(), MY_PREFIX + mapName, errHandler, BooleanField.INSTANCE, true);
	}

	@Override
	public void add(Address startAddr, Address endAddr) {
		try (Closeable c = lock.write()) {
			checkDeleted();
			propertyMap.paintRange(startAddr, endAddr, FIELD);
			program.setChanged(ProgramEvent.ADDRESS_PROPERTY_MAP_CHANGED, null, mapName);
		}
	}

	@Override
	public void add(AddressSetView addressSet) {

		try (Closeable c = lock.write()) {
			checkDeleted();
			AddressRangeIterator iter = addressSet.getAddressRanges();
			while (iter.hasNext()) {
				AddressRange range = iter.next();
				add(range.getMinAddress(), range.getMaxAddress());
			}
			program.setChanged(ProgramEvent.ADDRESS_PROPERTY_MAP_CHANGED, null, mapName);
		}
	}

	@Override
	public void set(AddressSetView addressSet) {
		try (Closeable c = lock.write()) {
			checkDeleted();
			clear();
			add(addressSet);
			program.setChanged(ProgramEvent.ADDRESS_PROPERTY_MAP_CHANGED, null, mapName);
		}
	}

	@Override
	public void remove(Address startAddr, Address endAddr) {
		try (Closeable c = lock.write()) {
			checkDeleted();
			propertyMap.clearRange(startAddr, endAddr);
			program.setChanged(ProgramEvent.ADDRESS_PROPERTY_MAP_CHANGED, null, mapName);
		}
	}

	@Override
	public void remove(AddressSetView addressSet) {
		try (Closeable c = lock.write()) {
			checkDeleted();
			AddressRangeIterator iter = addressSet.getAddressRanges();
			while (iter.hasNext()) {
				AddressRange range = iter.next();
				remove(range.getMinAddress(), range.getMaxAddress());
			}
			program.setChanged(ProgramEvent.ADDRESS_PROPERTY_MAP_CHANGED, null, mapName);
		}
	}

	@Override
	public AddressSet getAddressSet() {
		try (Closeable c = lock.read()) {
			checkDeleted();
			return propertyMap.getAddressSet();
		}
	}

	@Override
	public AddressIterator getAddresses() {
		try (Closeable c = lock.read()) {
			checkDeleted();
			if (propertyMap.isEmpty()) {
				return new EmptyAddressIterator();
			}
			AddressSet set = getAddressSet();
			return set.getAddresses(true);
		}
	}

	@Override
	public AddressRangeIterator getAddressRanges() {
		try (Closeable c = lock.read()) {
			checkDeleted();
			return propertyMap.getAddressRanges();
		}
	}

	@Override
	public void clear() {
		try (Closeable c = lock.write()) {
			checkDeleted();
			propertyMap.dispose();
			program.setChanged(ProgramEvent.ADDRESS_PROPERTY_MAP_CHANGED, null, mapName);
		}
	}

	@Override
	public boolean contains(Address addr) {
		try (Closeable c = lock.read()) {
			checkDeleted();
			return propertyMap.getValue(addr) != null;
		}
	}

	public void delete() {
		try (Closeable c = lock.write()) {
			invalid = true;
			propertyMap.dispose();
		}
	}

	/**
	 * Move the address range to a new starting address.
	 * @param fromAddr move from address
	 * @param toAddr move to address
	 * @param length number of address to move
	 * @param monitor task monitor
	 * @throws AddressOverflowException address out of bounds
	 * @throws CancelledException if cancelled
	 */
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws AddressOverflowException, CancelledException {
		try (Closeable c = lock.write()) {
			checkDeleted();
			Address rangeEnd = fromAddr.addNoWrap(length - 1);

			AddressSet currentSet = new AddressSet();
			AddressRangeIterator rangeIter = propertyMap.getAddressRanges(fromAddr, rangeEnd);
			while (rangeIter.hasNext()) {
				monitor.checkCancelled();
				currentSet.add(rangeIter.next());
			}

			propertyMap.clearRange(fromAddr, rangeEnd);

			rangeIter = currentSet.getAddressRanges();
			while (rangeIter.hasNext()) {
				monitor.checkCancelled();
				AddressRange range = rangeIter.next();
				Address startAddr = range.getMinAddress();
				Address endAddr = range.getMaxAddress();
				long offset = startAddr.subtract(fromAddr);
				startAddr = toAddr.add(offset);
				offset = endAddr.subtract(fromAddr);
				endAddr = toAddr.add(offset);
				propertyMap.paintRange(startAddr, endAddr, FIELD);
			}
		}
	}

	private void checkDeleted() {
		if (invalid) {
			throw new ConcurrentModificationException("AddressSetPropertyMap has been deleted.");
		}
	}

}
