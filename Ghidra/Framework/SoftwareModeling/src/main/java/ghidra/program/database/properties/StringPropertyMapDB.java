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
import ghidra.program.model.util.StringPropertyMap;
import ghidra.program.util.ChangeManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.prop.PropertyVisitor;
import ghidra.util.task.TaskMonitor;

/**
 * Property manager that deals with properties that are of
 * String type and stored with a database table.
 */
public class StringPropertyMapDB extends PropertyMapDB implements StringPropertyMap {

	/**
	 * Construct an String property map.
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
	public StringPropertyMapDB(DBHandle dbHandle, int openMode, ErrorHandler errHandler,
			ChangeManager changeMgr, AddressMap addrMap, String name, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		super(dbHandle, errHandler, changeMgr, addrMap, name);
		checkMapVersion(openMode, monitor);
	}

	/**
	 * @see ghidra.program.model.util.StringPropertyMap#add(ghidra.program.model.address.Address, java.lang.String)
	 */
	@Override
	public void add(Address addr, String value) {
		lock.acquire();
		try {
			long key = addrMap.getKey(addr, true);

			String oldValue = null;
			if (propertyTable == null) {
				createTable(StringField.INSTANCE);
			}
			else {
				oldValue = (String) cache.get(key);
				if (oldValue == null) {
					DBRecord rec = propertyTable.getRecord(key);
					if (rec != null) {
						oldValue = rec.getString(PROPERTY_VALUE_COL);
					}
				}
			}
			DBRecord rec = schema.createRecord(key);
			rec.setString(PROPERTY_VALUE_COL, value);
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

	/**
	 * @see ghidra.program.model.util.StringPropertyMap#getString(ghidra.program.model.address.Address)
	 */
	@Override
	public String getString(Address addr) {
		if (propertyTable == null) {
			return null;
		}

		String str = null;

		lock.acquire();
		try {
			long key = addrMap.getKey(addr, false);
			if (key == AddressMap.INVALID_ADDRESS_KEY) {
				return null;
			}
			str = (String) cache.get(key);
			if (str != null) {
				return str;
			}

			DBRecord rec = propertyTable.getRecord(key);
			if (rec == null) {
				return null;
			}
			str = rec.getString(PROPERTY_VALUE_COL);
		}
		catch (IOException e) {
			errHandler.dbError(e);

		}
		finally {
			lock.release();
		}

		return str;
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#getObject(ghidra.program.model.address.Address)
	 */
	@Override
	public Object getObject(Address addr) {
		return getString(addr);
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#applyValue(ghidra.util.prop.PropertyVisitor, ghidra.program.model.address.Address)
	 */
	@Override
	public void applyValue(PropertyVisitor visitor, Address addr) {
		String str = getString(addr);
		if (str != null) {
			visitor.visit(str);
		}
	}

}
