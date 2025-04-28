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
package ghidra.program.database.properties;

import java.io.IOException;
import java.util.function.Function;

import db.*;
import db.util.ErrorHandler;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.util.LongPropertyMap;
import ghidra.program.util.ChangeManager;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Property manager that deals with properties that are of
 * long type and stored with a database table.
 */
public class LongPropertyMapDB extends PropertyMapDB<Long> implements LongPropertyMap {

	/**
	 * A single record reader function is used to avoid the use of a lambda form which could
	 * cause multiple synthetic class instantiations.
	 */
	private Function<Long, Long> valueReader = addrKey -> {
		Table table = propertyTable;
		DBRecord rec = null;
		try {
			if (table != null) {
				rec = table.getRecord(addrKey);
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return rec != null ? rec.getLongValue(PROPERTY_VALUE_COL) : null;
	};

	/**
	 * Construct a long property map.
	 * @param dbHandle database handle.
	 * @param openMode the mode that the program was openned in or null if instantiated during
	 * cache invalidate.  Used to detect versioning error only.
	 * @param errHandler database error handler.
	 * @param changeMgr change manager for event notification	 
	 * @param addrMap address map.
	 * @param name property name.
	 * @param monitor progress monitor that is only used when upgrading
	 * @throws VersionException if the database version is not the expected version.
	 * @throws CancelledException if the user cancels the upgrade operation.
	 * @throws IOException if a database io error occurs.
	 */
	public LongPropertyMapDB(DBHandle dbHandle, OpenMode openMode, ErrorHandler errHandler,
			ChangeManager changeMgr, AddressMap addrMap, String name, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		super(dbHandle, errHandler, changeMgr, addrMap, name);
		checkMapVersion(openMode, monitor);
	}

	@Override
	public void add(Address addr, long value) {
		lock.acquire();
		try {
			checkDeleted();
			Long oldValue = null;
			long addrKey = addrMap.getKey(addr, true);
			if (propertyTable == null) {
				createTable(LongField.INSTANCE);
			}
			else {
				oldValue = cache.get(addrKey);
				if (oldValue == null) {
					oldValue = valueReader.apply(addrKey);
				}
			}
			DBRecord rec = schema.createRecord(addrKey);
			rec.setLongValue(PROPERTY_VALUE_COL, value);
			propertyTable.putRecord(rec);
			cache.put(addrKey, value);
			changeMgr.setPropertyChanged(name, addr, oldValue, value);
		}
		catch (IOException e) {
			errHandler.dbError(e);

		}
		finally {
			lock.release();
		}
	}

	@Override
	public long getLong(Address addr) throws NoValueException {
		Long value = get(addr);
		if (value == null) {
			throw NO_VALUE_EXCEPTION;
		}
		return value;
	}

	@Override
	public Long get(Address addr) {
		validate(lock);
		Table table = propertyTable;
		if (table == null) {
			return null;
		}
		long addrKey = addrMap.getKey(addr, false);
		if (addrKey == AddressMap.INVALID_ADDRESS_KEY) {
			return null;
		}
		return cache.computeIfAbsent(addrKey, valueReader);
	}

}
