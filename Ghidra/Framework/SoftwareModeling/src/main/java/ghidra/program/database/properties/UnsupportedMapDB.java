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

import javax.help.UnsupportedOperationException;

import db.DBHandle;
import db.util.ErrorHandler;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.util.ChangeManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * This class provides a dummy map for an unsupported map.
 */
public class UnsupportedMapDB extends PropertyMapDB<Object> {

	/**
	 * Construct a dummy property map.
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
	UnsupportedMapDB(DBHandle dbHandle, OpenMode openMode, ErrorHandler errHandler,
			ChangeManager changeMgr, AddressMap addrMap, String name, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		super(dbHandle, errHandler, changeMgr, addrMap, name);
		checkMapVersion(openMode, monitor);
	}

	@Override
	public Class<Object> getValueClass() {
		return null;
	}

	@Override
	public Object get(Address addr) {
		return null;
	}

	@Override
	public boolean hasProperty(Address addr) {
		return false;
	}

	@Override
	public void add(Address addr, Object value) {
		throw new UnsupportedOperationException();
	}

}
