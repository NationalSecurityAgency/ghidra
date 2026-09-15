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
package ghidra.program.database;

import java.util.ConcurrentModificationException;

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.util.AddressRangeMapDB;
import ghidra.program.model.address.*;
import ghidra.program.util.ProgramEvent;
import ghidra.util.Lock;
import ghidra.util.Lock.Closeable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class IntRangeMapDB implements IntRangeMap {

	private static final String MY_PREFIX = "IntMap - ";
	public static final String TABLE_PREFIX = AddressRangeMapDB.RANGE_MAP_TABLE_PREFIX + MY_PREFIX;

	private ProgramDB program;
	private String mapName;
	private Lock lock;
	private AddressRangeMapDB propertyMap;
	private boolean invalid;

	public static IntRangeMapDB getPropertyMap(ProgramDB program, String mapName,
			ErrorHandler errHandler, AddressMap addrMap, Lock lock) {

		try (Closeable c = lock.read()) {
			DBHandle dbh = program.getDBHandle();
			String tableName = IntRangeMapDB.TABLE_PREFIX + mapName;
			if (dbh.getTable(tableName) != null) {
				return new IntRangeMapDB(program, mapName, program, addrMap, lock);
			}
		}
		return null;
	}

	public static IntRangeMapDB createPropertyMap(ProgramDB program, String mapName,
			ErrorHandler errHandler, AddressMap addrMap, Lock lock) throws DuplicateNameException {
		try (Closeable c = lock.write()) {
			DBHandle dbh = program.getDBHandle();
			String tableName = TABLE_PREFIX + mapName;
			if (dbh.getTable(tableName) != null) {
				throw new DuplicateNameException(
					"Address Set Property Map named " + mapName + " already exists.");
			}

			return new IntRangeMapDB(program, mapName, program, addrMap, lock);
		}
	}

	private IntRangeMapDB(ProgramDB program, String mapName, ErrorHandler errHandler,
			AddressMap addrMap, Lock lock) {
		this.program = program;
		this.mapName = mapName;
		this.lock = lock;

		propertyMap = new AddressRangeMapDB(program.getDBHandle(), program.getAddressMap(),
			program.getLock(), MY_PREFIX + mapName, errHandler, IntField.INSTANCE, true);

	}

	public void delete() {
		invalid = true;
		propertyMap.dispose();
	}

	private void checkDeleted() {
		if (invalid) {
			throw new ConcurrentModificationException("AddressSetPropertyMap has been deleted.");
		}
	}

	@Override
	public void setValue(Address start, Address end, int value) {
		checkDeleted();
		try (Closeable c = lock.write()) {
			propertyMap.paintRange(start, end, new IntField(value));
			program.setChanged(ProgramEvent.INT_PROPERTY_MAP_CHANGED, null, mapName);
		}
	}

	@Override
	public void setValue(AddressSetView addresses, int value) {
		checkDeleted();
		try (Closeable c = lock.write()) {
			AddressRangeIterator iter = addresses.getAddressRanges();
			while (iter.hasNext()) {
				AddressRange range = iter.next();
				setValue(range.getMinAddress(), range.getMaxAddress(), value);
			}
			program.setChanged(ProgramEvent.INT_PROPERTY_MAP_CHANGED, null, mapName);
		}
	}

	@Override
	public void clearAll() {
		checkDeleted();
		try (Closeable c = lock.write()) {
			propertyMap.dispose();
			program.setChanged(ProgramEvent.INT_PROPERTY_MAP_CHANGED, null, mapName);
		}
	}

	@Override
	public void clearValue(Address startAddr, Address endAddr) {
		checkDeleted();
		try (Closeable c = lock.write()) {
			propertyMap.clearRange(startAddr, endAddr);
			program.setChanged(ProgramEvent.INT_PROPERTY_MAP_CHANGED, null, mapName);
		}
	}

	@Override
	public void clearValue(AddressSetView addresses) {
		checkDeleted();
		try (Closeable c = lock.write()) {
			AddressRangeIterator iter = addresses.getAddressRanges();
			while (iter.hasNext()) {
				AddressRange range = iter.next();
				clearValue(range.getMinAddress(), range.getMaxAddress());
			}
			program.setChanged(ProgramEvent.INT_PROPERTY_MAP_CHANGED, null, mapName);
		}
	}

	@Override
	public Integer getValue(Address address) {
		checkDeleted();
		try (Closeable c = lock.read()) {
			Field value = propertyMap.getValue(address);
			if (value == null) {
				return null;
			}
			return ((IntField) value).getIntValue();
		}
	}

	@Override
	public AddressSet getAddressSet() {
		checkDeleted();
		try (Closeable c = lock.read()) {
			return propertyMap.getAddressSet();
		}
	}

	@Override
	public AddressSet getAddressSet(int value) {
		checkDeleted();
		try (Closeable c = lock.read()) {
			return propertyMap.getAddressSet(new IntField(value));
		}
	}

	/**
	 * Move the address range to a new starting address.
	 * @param fromAddr move from address
	 * @param toAddr move to address
	 * @param length number of address to move
	 * @param monitor the task monitor
	 * @throws CancelledException if cancelled
	 */
	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		checkDeleted();
		try (Closeable c = lock.write()) {
			propertyMap.moveAddressRange(fromAddr, toAddr, length, monitor);
		}
	}

}
