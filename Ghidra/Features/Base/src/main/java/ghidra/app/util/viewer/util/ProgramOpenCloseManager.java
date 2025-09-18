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

import java.util.ArrayList;
import java.util.List;

import javax.swing.event.ChangeListener;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Manages the open/close state of various listing regions. This includes structures, arrays, and
 * function variables.
 */
public class ProgramOpenCloseManager {
	private DataOpenCloseManager dataOpenCloseManager = new DataOpenCloseManager();
	private List<ChangeListener> listeners = new ArrayList<>();
	private AddressBasedOpenCloseManager variablesOpenCloseManager = new AddressBasedOpenCloseManager();

	/**
	 * Sets whether or not to display function variables at the given address.
	 * @param functionAddress the address of the function
	 * @param open true to display function variables, false to to hide them
	 */
	public void setFunctionVariablesOpen(Address functionAddress, boolean open) {
		if (open) {
			variablesOpenCloseManager.open(functionAddress);
		}
		else {
			variablesOpenCloseManager.close(functionAddress);
		}
		notifyListeners();
	}

	/**
	 * Checks if the function variables are being shown at the given function address.
	 * @param functionAddress the address of the function to check
	 * @return true if the variables are being displayed
	 */
	public boolean isFunctionVariablesOpen(Address functionAddress) {
		return variablesOpenCloseManager.isOpen(functionAddress);
	}

	/**
	 * Sets whether or not function variables are being shown by globally. This essentially sets
	 * the default state, but the state can be overridden at specific functions. 
	 * @param open if true, then the function variables are displayed
	 */
	public void setAllFunctionVariablesOpen(boolean open) {
		if (open) {
			variablesOpenCloseManager.openAll();
		}
		else {
			variablesOpenCloseManager.closeAll();
		}
		notifyListeners();
	}

	public boolean isAllFunctionVariablesOpen() {
		return variablesOpenCloseManager.isOpenByDefault();
	}

	/**
	 * Marks the given data as open.  This method notifies listeners of changes.
	 * @param data The data to open.
	 */
	public void openData(Data data) {
		dataOpenCloseManager.openData(data);
		notifyListeners();
	}

	/**
	 * Marks the given data as open.  This method notifies listeners of changes.
	 * @param data The data to open.
	 */
	public void closeData(Data data) {
		dataOpenCloseManager.closeData(data);
		notifyListeners();
	}

	/**
	 * Tests if the data at the given address is open
	 * @param address the address to test if open
	 * @return true if the data at the address is open.
	 */
	public boolean isDataOpen(Address address) {
		return dataOpenCloseManager.isDataOpen(address, null);
	}

	public boolean isDataOpen(Data data) {
		return dataOpenCloseManager.isDataOpen(data);
	}

	/**
	 * Returns the index of the component that is open at the given address.
	 * @param data the data to get the index for
	 * @return the index of the component that is open for the given data
	 */
	public int getOpenDataIndex(Data data) {
		return dataOpenCloseManager.getOpenDataIndex(data.getMinAddress(), data.getComponentPath());
	}

	public void toggleDataOpen(Data data) {
		dataOpenCloseManager.toggleOpen(data);
		notifyListeners();
	}

	public void openAllData(Program program, AddressSetView addresses, TaskMonitor monitor) {
		dataOpenCloseManager.openAllData(program, addresses, monitor);
		notifyListeners();
	}

	public void closeAllData(Program program, AddressSetView addresses, TaskMonitor monitor) {
		dataOpenCloseManager.closeAllData(program, addresses, monitor);
		notifyListeners();
	}

	public void openDataRecursively(Data data, TaskMonitor monitor) {
		dataOpenCloseManager.toggleDataRecursively(data, true, monitor);
		notifyListeners();
	}

	public void closeDataRecursively(Data data, TaskMonitor monitor) {
		dataOpenCloseManager.toggleDataRecursively(data, false, monitor);
		notifyListeners();
	}

	/**
	 * Adds a change listener to be notified when a location is open or closed.
	 * @param l the listener to be notified.
	 */
	public void addChangeListener(ChangeListener l) {
		listeners.add(l);
	}

	/**
	 * Removes the listener.
	 * @param l the listener to remove.
	 */
	public void removeChangeListener(ChangeListener l) {
		listeners.remove(l);
	}

	private void notifyListeners() {
		for (ChangeListener l : listeners) {
			l.stateChanged(null);
		}
	}
}
