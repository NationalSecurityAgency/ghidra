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
package ghidra.trace.database.program;

import java.util.Iterator;

import ghidra.program.model.address.Address;
import ghidra.program.model.util.*;
import ghidra.util.Saveable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class DBTraceProgramViewPropertyMapManager implements PropertyMapManager {
	protected final DBTraceProgramView program;

	public DBTraceProgramViewPropertyMapManager(DBTraceProgramView program) {
		this.program = program;
	}

	@Override
	public IntPropertyMap createIntPropertyMap(String propertyName) throws DuplicateNameException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public LongPropertyMap createLongPropertyMap(String propertyName)
			throws DuplicateNameException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public StringPropertyMap createStringPropertyMap(String propertyName)
			throws DuplicateNameException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public ObjectPropertyMap createObjectPropertyMap(String propertyName,
			Class<? extends Saveable> objectClass) throws DuplicateNameException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public VoidPropertyMap createVoidPropertyMap(String propertyName)
			throws DuplicateNameException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public PropertyMap getPropertyMap(String propertyName) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public IntPropertyMap getIntPropertyMap(String propertyName) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public LongPropertyMap getLongPropertyMap(String propertyName) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public StringPropertyMap getStringPropertyMap(String propertyName) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public ObjectPropertyMap getObjectPropertyMap(String propertyName) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public VoidPropertyMap getVoidPropertyMap(String propertyName) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean removePropertyMap(String propertyName) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Iterator<String> propertyManagers() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void removeAll(Address addr) {
		// TODO Auto-generated method stub

	}

	@Override
	public void removeAll(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		// TODO Auto-generated method stub

	}
}
