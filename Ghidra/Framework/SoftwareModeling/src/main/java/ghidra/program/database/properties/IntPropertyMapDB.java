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
import ghidra.program.model.util.IntPropertyMap;
import ghidra.program.util.ChangeManager;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Property manager that deals with properties that are of
 * int type and stored with a database table.
 */
public class IntPropertyMapDB extends PropertyMapDB<Integer> implements IntPropertyMap {

	/**
	 * A single non-capturing lambda record reader function is used to avoid the possibility of 
	 * multiple synthetic class instantiations.
	 */
	private Function<Long, Integer> valueReader = addrKey -> {
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
		return rec != null ? rec.getIntValue(PROPERTY_VALUE_COL) : null;
	};

	/**
	 * Construct a integer property map.
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
	public IntPropertyMapDB(DBHandle dbHandle, OpenMode openMode, ErrorHandler errHandler,
			ChangeManager changeMgr, AddressMap addrMap, String name, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		super(dbHandle, errHandler, changeMgr, addrMap, name);
		checkMapVersion(openMode, monitor);
	}

	@Override
	public void add(Address addr, int value) {
		lock.acquire();
		try {
			checkDeleted();
			Integer oldValue = null;
			long addrKey = addrMap.getKey(addr, true);
			if (propertyTable == null) {
				createTable(IntField.INSTANCE);
			}
			else {
				oldValue = cache.get(addrKey);
				if (oldValue == null) {
					oldValue = valueReader.apply(addrKey);
				}
			}
			DBRecord rec = schema.createRecord(addrKey);
			rec.setIntValue(PROPERTY_VALUE_COL, value);
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
	public int getInt(Address addr) throws NoValueException {
		Integer value = get(addr);
		if (value == null) {
			throw NO_VALUE_EXCEPTION;
		}
		return value;
	}

	@Override
	public Integer get(Address addr) {
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
