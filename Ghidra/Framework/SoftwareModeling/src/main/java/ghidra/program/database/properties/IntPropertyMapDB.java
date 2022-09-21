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

import db.*;
import db.util.ErrorHandler;
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
	 * Construct a integer property map.
	 * @param dbHandle database handle.
	 * @param openMode the mode that the program was openned in.
	 * @param errHandler database error handler.
	 * @param changeMgr change manager for event notification	 
	 * @param addrMap address map.
	 * @param name property name.
	 * @param monitor progress monitor that is only used when upgrading
	 * @throws VersionException if the database version is not the expected version.
	 * @throws CancelledException if the user cancels the upgrade operation.
	 * @throws IOException if a database io error occurs.
	 */
	public IntPropertyMapDB(DBHandle dbHandle, int openMode, ErrorHandler errHandler,
			ChangeManager changeMgr, AddressMap addrMap, String name, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		super(dbHandle, errHandler, changeMgr, addrMap, name);
		checkMapVersion(openMode, monitor);
	}

	@Override
	public void add(Address addr, int value) {
		lock.acquire();
		try {
			Integer oldValue = null;

			long key = addrMap.getKey(addr, true);

			if (propertyTable == null) {
				createTable(IntField.INSTANCE);
			}
			else {
				oldValue = (Integer) cache.get(key);
				if (oldValue == null) {
					DBRecord rec = propertyTable.getRecord(key);
					if (rec != null) {
						oldValue = rec.getIntValue(PROPERTY_VALUE_COL);
					}
				}
			}
			DBRecord rec = schema.createRecord(key);

			rec.setIntValue(PROPERTY_VALUE_COL, value);
			propertyTable.putRecord(rec);
			cache.put(key, value);

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
		if (propertyTable == null) {
			throw NO_VALUE_EXCEPTION;
		}

		lock.acquire();
		try {
			long key = addrMap.getKey(addr, false);
			if (key == AddressMap.INVALID_ADDRESS_KEY) {
				return 0;
			}
			Object obj = cache.get(key);
			if (obj != null) {
				return ((Integer) obj).intValue();
			}

			DBRecord rec = propertyTable.getRecord(key);
			if (rec == null) {
				throw NO_VALUE_EXCEPTION;
			}
			return rec.getIntValue(PROPERTY_VALUE_COL);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return 0;
	}

	@Override
	public Integer get(Address addr) {
		try {
			return getInt(addr);
		}
		catch (NoValueException e) {
			return null;
		}
	}

}
