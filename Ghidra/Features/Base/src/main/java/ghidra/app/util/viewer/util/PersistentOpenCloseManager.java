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
package ghidra.app.util.viewer.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.program.model.util.VoidPropertyMap;

/**
 * Address based open/close management that uses the {@link ProgramUserData} to persist the 
 * open/close state for that address. Currently used for persisting the open/close state
 * of functions in the listing.
 */
public class PersistentOpenCloseManager implements OpenCloseManager {
	private boolean openByDefault = true;
	private VoidPropertyMap booleanProperty;
	private ProgramUserData programUserData;

	// Often, isOpen will be called on the same function address many times in a row so cache
	// the last address and result
	private Address cachedAddress;
	private boolean cachedResult;
	private String defaultOpenClosePropertyname;

	public PersistentOpenCloseManager(ProgramUserData data, String owner, String propertyName) {
		this.defaultOpenClosePropertyname = propertyName + "Default";
		programUserData = data;

		int tx = programUserData.startTransaction();
		try {
			booleanProperty =
				programUserData.getBooleanProperty(owner, propertyName, true);
		}
		finally {
			programUserData.endTransaction(tx);
		}

		// Get the default open state. Only addresses different from default have properties stored.
		String functionState =
			programUserData.getStringProperty(defaultOpenClosePropertyname, "Open");
		openByDefault = functionState.equals("Open");
	}

	@Override
	public boolean isOpen(Address address) {
		if (address.equals(cachedAddress)) {
			return cachedResult;
		}
		cachedAddress = address;
		boolean contains = booleanProperty.hasProperty(address);
		cachedResult = openByDefault ? !contains : contains;
		return cachedResult;
	}

	@Override
	public void open(Address address) {
		cachedAddress = null;
		if (openByDefault) {
			removeAddressProperty(address);
		}
		else {
			addAddressProperty(address);
		}
	}

	@Override
	public void close(Address address) {
		cachedAddress = null;
		if (openByDefault) {
			addAddressProperty(address);
		}
		else {
			removeAddressProperty(address);
		}
	}

	@Override
	public boolean isOpenByDefault() {
		return openByDefault;
	}

	@Override
	public void openAll() {
		cachedAddress = null;
		openByDefault = true;
		clearProperties();
		programUserData.setStringProperty(defaultOpenClosePropertyname, "Open");
	}

	@Override
	public void closeAll() {
		cachedAddress = null;
		openByDefault = false;
		clearProperties();
		programUserData.setStringProperty(defaultOpenClosePropertyname, "Closed");
	}

	private void addAddressProperty(Address address) {
		int tx = programUserData.startTransaction();
		try {
			booleanProperty.add(address);
		}
		finally {
			programUserData.endTransaction(tx);
		}
	}

	private void removeAddressProperty(Address address) {
		int tx = programUserData.startTransaction();
		try {
			booleanProperty.remove(address);
		}
		finally {
			programUserData.endTransaction(tx);
		}
	}

	private void clearProperties() {
		int tx = programUserData.startTransaction();
		try {
			booleanProperty.clear();
		}
		finally {
			programUserData.endTransaction(tx);
		}

	}
}
