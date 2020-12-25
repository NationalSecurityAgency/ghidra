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
import ghidra.program.util.ChangeManager;
import ghidra.util.Lock;
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

		lock.acquire();
		try {
			String tableName = AddressSetPropertyMapDB.TABLE_PREFIX + mapName;

			DBHandle dbh = program.getDBHandle();
			if (dbh.getTable(tableName) != null) {
				return new AddressSetPropertyMapDB(program, mapName, program, addrMap, lock);
			}
		}
		finally {
			lock.release();
		}
		return null;
	}

	public static AddressSetPropertyMapDB createPropertyMap(ProgramDB program, String mapName,
			ErrorHandler errHandler, AddressMap addrMap, Lock lock) throws DuplicateNameException {
		lock.acquire();
		try {
			DBHandle dbh = program.getDBHandle();
			String tableName = AddressSetPropertyMapDB.TABLE_PREFIX + mapName;
			if (dbh.getTable(tableName) != null) {
				throw new DuplicateNameException(
					"Address Set Property Map named " + mapName + " already exists.");
			}

			return new AddressSetPropertyMapDB(program, mapName, program, addrMap, lock);
		}
		finally {
			lock.release();
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
		checkDeleted();
		lock.acquire();
		try {
			propertyMap.paintRange(startAddr, endAddr, FIELD);
			program.setChanged(ChangeManager.DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED, null, mapName);
		}
		finally {
			lock.release();
		}

	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.util.AddressSetPropertyMap#add(ghidra.program.model.address.AddressSet)
	 */
	@Override
	public void add(AddressSetView addressSet) {
		checkDeleted();

		lock.acquire();
		try {
			AddressRangeIterator iter = addressSet.getAddressRanges();
			while (iter.hasNext()) {
				AddressRange range = iter.next();
				add(range.getMinAddress(), range.getMaxAddress());
			}
			program.setChanged(ChangeManager.DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED, null, mapName);
		}
		finally {
			lock.release();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.util.AddressSetPropertyMap#set(ghidra.program.model.address.AddressSet)
	 */
	@Override
	public void set(AddressSetView addressSet) {
		checkDeleted();
		lock.acquire();
		try {
			clear();
			add(addressSet);
			program.setChanged(ChangeManager.DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED, null, mapName);
		}
		finally {
			lock.release();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.util.AddressSetPropertyMap#remove(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public void remove(Address startAddr, Address endAddr) {
		checkDeleted();
		lock.acquire();
		try {
			propertyMap.clearRange(startAddr, endAddr);
			program.setChanged(ChangeManager.DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED, null, mapName);
		}
		finally {
			lock.release();
		}

	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.util.AddressSetPropertyMap#remove(ghidra.program.model.address.AddressSet)
	 */
	@Override
	public void remove(AddressSetView addressSet) {
		checkDeleted();
		lock.acquire();
		try {
			AddressRangeIterator iter = addressSet.getAddressRanges();
			while (iter.hasNext()) {
				AddressRange range = iter.next();
				remove(range.getMinAddress(), range.getMaxAddress());
			}
			program.setChanged(ChangeManager.DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED, null, mapName);
		}
		finally {
			lock.release();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.util.AddressSetPropertyMap#getAddressSet()
	 */
	@Override
	public AddressSet getAddressSet() {
		checkDeleted();
		lock.acquire();
		try {
			return propertyMap.getAddressSet();
		}
		finally {
			lock.release();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.util.AddressSetPropertyMap#getAddresses()
	 */
	@Override
	public AddressIterator getAddresses() {
		checkDeleted();
		lock.acquire();
		try {
			if (propertyMap.isEmpty()) {
				return new EmptyAddressIterator();
			}
			AddressSet set = getAddressSet();
			return set.getAddresses(true);
		}
		finally {
			lock.release();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.util.AddressSetPropertyMap#getAddressRanges()
	 */
	@Override
	public AddressRangeIterator getAddressRanges() {
		checkDeleted();
		lock.acquire();
		try {
			return propertyMap.getAddressRanges();
		}
		finally {
			lock.release();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.util.AddressSetPropertyMap#clear()
	 */
	@Override
	public void clear() {
		checkDeleted();
		lock.acquire();
		try {
			propertyMap.dispose();
			program.setChanged(ChangeManager.DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED, null, mapName);
		}
		finally {
			lock.release();
		}

	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.util.AddressSetPropertyMap#contains(ghidra.program.model.address.Address)
	 */
	@Override
	public boolean contains(Address addr) {
		checkDeleted();
		lock.acquire();
		try {
			return propertyMap.getValue(addr) != null;
		}
		finally {
			lock.release();
		}
	}

	public void delete() {
		propertyMap.dispose();
		invalid = true;
	}

	/**
	 * Move the address range to a new starting address.
	 * @param fromAddr move from address
	 * @param toAddr move to address
	 * @param length number of address to move
	 * @param monitor
	 * @throws CancelledException
	 */
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws AddressOverflowException, CancelledException {
		lock.acquire();
		try {

			Address rangeEnd = fromAddr.addNoWrap(length - 1);

			AddressSet currentSet = new AddressSet();
			AddressRangeIterator rangeIter = propertyMap.getAddressRanges(fromAddr, rangeEnd);
			while (rangeIter.hasNext()) {
				monitor.checkCanceled();
				currentSet.add(rangeIter.next());
			}

			propertyMap.clearRange(fromAddr, rangeEnd);

			rangeIter = currentSet.getAddressRanges();
			while (rangeIter.hasNext()) {
				monitor.checkCanceled();
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
		finally {
			lock.release();
		}
	}

	private void checkDeleted() {
		if (invalid) {
			throw new ConcurrentModificationException("AddressSetPropertyMap has been deleted.");
		}
	}

}
