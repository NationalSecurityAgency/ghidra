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

import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.util.VoidPropertyMap;
import ghidra.program.util.ChangeManager;
import ghidra.util.exception.*;
import ghidra.util.prop.PropertyVisitor;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

import db.DBHandle;
import db.DBRecord;
import db.util.ErrorHandler;

/**
 * Property manager that deals with properties that are of
 * "void" type, which is a marker for whether a property exists.
 * Records contain only a address key are stored within the underlying database table.
 */
public class VoidPropertyMapDB extends PropertyMapDB implements VoidPropertyMap {

	private static Object VOID_OBJECT = new Object();

	/**
	 * Construct an void object property map.
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
	public VoidPropertyMapDB(DBHandle dbHandle, int openMode, ErrorHandler errHandler,
			ChangeManager changeMgr, AddressMap addrMap, String name, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		super(dbHandle, errHandler, changeMgr, addrMap, name);
		checkMapVersion(openMode, monitor);
	}

	/**
	 * @see ghidra.program.model.util.VoidPropertyMap#add(ghidra.program.model.address.Address)
	 */
	public void add(Address addr) {
		lock.acquire();
		try {
			long key = addrMap.getKey(addr, true);
			Boolean oldValue = new Boolean(hasProperty(addr));

			if (propertyTable == null) {
				createTable(null);
			}
			DBRecord rec = schema.createRecord(key);
			propertyTable.putRecord(rec);
			cache.put(key, VOID_OBJECT);
			changeMgr.setPropertyChanged(name, addr, oldValue, new Boolean(true));
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#applyValue(ghidra.util.prop.PropertyVisitor, ghidra.program.model.address.Address)
	 */
	public void applyValue(PropertyVisitor visitor, Address addr) {
		if (hasProperty(addr)) {
			visitor.visit();
		}
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#getObject(ghidra.program.model.address.Address)
	 */
	public Object getObject(Address addr) {
		if (hasProperty(addr)) {
			return Boolean.TRUE;
		}
		return null;
	}

}
