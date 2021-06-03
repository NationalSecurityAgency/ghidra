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

import java.util.*;

import javax.swing.event.ChangeListener;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Manages the open/close state of structures and arrays at specific addresses.
 */
public class OpenCloseManager {
	/**
	 * The map stores an int[] for each address that has something open.
	 * If map.get(address) returns null then outermost level is closed.
	 */
	private Map<Address, int[]> map = new HashMap<>();

	private List<ChangeListener> listeners = new ArrayList<>();

	/**
	 * Marks the given data as open.  This method notifies listeners of changes.
	 * @param data The data to open.
	 * @return true if the data location was opened (false if already open or can't be opened)
	 */
	public boolean openData(Data data) {
		if (data.getComponent(0) == null) {
			return false;
		}

		Address addr = data.getMinAddress();
		int[] path = data.getComponentPath();
		if (isOpen(addr, path)) {
			return false;
		}
		open(addr, path);
		notifyDataToggled();
		return true;
	}

	/**
	 * Marks the given data as open.  This method notifies listeners of changes.
	 * @param data The data to open.
	 */
	public void closeData(Data data) {
		if (data.getComponent(0) == null) {
			return;
		}
		Address addr = data.getMinAddress();
		int[] path = data.getComponentPath();
		if (!isOpen(addr, path)) {
			return;
		}
		close(addr, path);
		notifyDataToggled();
	}

	/**
	 * Marks the data path (and any parents at that address) as open
	 * @param address the address to open
	 * @param path the data component path to open
	 */
	private void open(Address address, int[] path) {
		int pathSize = path.length;
		int[] levels = map.get(address);
		if ((levels == null) || (pathSize >= levels.length)) {
			exactOpen(address, path);
			return;
		}
		levels[0] = 0;
		int i = 0;
		for (; i < pathSize; i++) {
			if (levels[i + 1] != path[i]) {
				if (levels[i + 1] != -1) {
					exactOpen(address, path);
					return;
				}
				levels[i + 1] = path[i];
			}
		}
		map.put(address, levels);
	}

	private void exactOpen(Address address, int[] path) {
		int pathSize = path.length;
		int[] newLevels = new int[pathSize + 1];
		newLevels[0] = 0;
		System.arraycopy(path, 0, newLevels, 1, pathSize);
		map.put(address, newLevels);
	}

	/**
	 * Marks the composite at the given address and component path as closed
	 * @param address the address of the composite to close
	 * @param path the component path of the composite to close. Used for
	 * composites inside of other composites.
	 */
	private void close(Address address, int[] path) {
		int[] levels = map.get(address);
		if (levels == null) {
			return;
		}
		int levelSize = levels.length;
		int pathSize = 0;
		if (path != null) {
			pathSize = path.length;
		}
		if (levelSize < pathSize + 1) {
			return;
		}
		for (int i = 0; i < pathSize; i++) {
			if (levels[i + 1] == -1) {
				continue;
			}
			if (levels[i + 1] != path[i]) {
				return;
			}
		}
		levels[pathSize] = -1;
		int actualLength = computeActualLength(levels);
		if (actualLength == 0) {
			map.remove(address);
			return;
		}
		int[] newLevels = levels;
		if (actualLength < levelSize) {
			newLevels = new int[actualLength];
			System.arraycopy(levels, 0, newLevels, 0, actualLength);
		}
		map.put(address, newLevels);
	}

	private int computeActualLength(int[] levels) {
		int size = levels.length;
		for (int i = size - 1; i >= 0; i--) {
			if (levels[i] != -1) {
				return i + 1;
			}
		}
		return 0;
	}

	/**
	 * Tests if the data at the given address is open
	 * @param address the address to test if open
	 */
	public boolean isOpen(Address address) {
		return isOpen(address, null);
	}

	/**
	 * Test is the data at the given address and component path is open
	 * @param address the address to test
	 * @param path the component path to test.
	 */
	public boolean isOpen(Address address, int[] path) {
		int[] levels = map.get(address);
		if (levels == null) {
			return false;
		}
		if ((path == null) || (path.length == 0)) {
			return ((levels.length > 0) && (levels[0] != -1));
		}
		int levelSize = levels.length;
		int pathSize = path.length;
		if (pathSize >= levelSize) {
			return false;
		}
		for (int i = 0; i < pathSize; i++) {
			if (levels[i + 1] == -1) {
				return false;
			}
			if (levels[i + 1] != path[i]) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Returns the index of the component that is open at the given address.
	 * @param address the address to find the open index.
	 * @param path the component path.
	 */
	public int getOpenIndex(Address address, int[] path) {
		int[] levels = map.get(address);
		if ((levels == null) || (levels.length == 0)) {
			return -1;
		}
		int levelsSize = levels.length;
		int pathSize = 0;
		if (path != null) {
			pathSize = path.length;
		}
		if (pathSize + 2 <= levelsSize) {
			return levels[pathSize + 1];
		}
		return -1;
	}

	public boolean isOpen(Data data) {
		return isOpen(data.getMinAddress(), data.getComponentPath());
	}

	public void toggleOpen(Data data) {
		toggleTopLevelData(data);

		notifyDataToggled();
	}

	private void toggleTopLevelData(Data data) {
		if (data.getComponent(0) == null) {
			return;
		}
		Address addr = data.getMinAddress();
		int[] path = data.getComponentPath();

		if (isOpen(addr, path)) {
			close(addr, path);
		}
		else {
			open(addr, path);
		}
	}

	private void notifyDataToggled() {
		for (ChangeListener l : listeners) {
			l.stateChanged(null);
		}
	}

	public void openAllData(Program program, AddressSetView addresses, TaskMonitor monitor) {
		toggleAllDataInAddresses(true, program, addresses, monitor);
	}

	private void toggleAllDataInAddresses(boolean open, Program program, AddressSetView addresses,
			TaskMonitor monitor) {
		monitor.initialize(addresses.getNumAddresses());
		Address start = addresses.getMinAddress();

		Listing listing = program.getListing();
		DataIterator iterator = listing.getData(addresses, true);
		while (iterator.hasNext()) {
			if (monitor.isCancelled()) {
				return;
			}

			Data data = iterator.next();

			toggleDataRecursively(data, open, monitor);

			Address max = data.getMaxAddress();
			long progress = max.subtract(start);

			monitor.setProgress(progress);
		}

		notifyDataToggled();
	}

	public void openAllData(Data data, TaskMonitor monitor) {
		toggleDataRecursively(data, true, monitor);

		notifyDataToggled();
	}

	public void closeAllData(Program program, AddressSetView addresses, TaskMonitor monitor) {
		toggleAllDataInAddresses(false, program, addresses, monitor);
	}

	public void closeAllData(Data data, TaskMonitor monitor) {
		toggleDataRecursively(data, false, monitor);

		notifyDataToggled();
	}

	private void toggleDataRecursively(Data data, boolean openState, TaskMonitor monitor) {
		if (data == null && !monitor.isCancelled()) {
			return;
		}

		if (isOpen(data) != openState) {
			toggleTopLevelData(data);
		}
		int componentCount = data.getNumComponents();

		// if the data is an array and its elements are not the type that can be opened, then bail
		if (componentCount > 0 && data.isArray()) {
			Data component = data.getComponent(0);
			if (component.getNumComponents() == 0) {
				return;
			}
		}
		TaskMonitor noProgressMonitor = new NoProgressMonitor(monitor);
		for (int i = 0; i < componentCount && !monitor.isCancelled(); i++) {
			monitor.incrementProgress(1);
			toggleDataRecursivlyUsingSubMonitor(data.getComponent(i), openState, noProgressMonitor);
		}
	}

	private void toggleDataRecursivlyUsingSubMonitor(Data data, boolean openState,
			TaskMonitor monitor) {
		if (data == null && !monitor.isCancelled()) {
			return;
		}

		if (isOpen(data) != openState) {
			toggleTopLevelData(data);
		}

		int componentCount = data.getNumComponents();
		for (int i = 0; i < componentCount && !monitor.isCancelled(); i++) {
			toggleDataRecursivlyUsingSubMonitor(data.getComponent(i), openState, monitor);
		}
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

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class NoProgressMonitor extends TaskMonitorAdapter {

		private final TaskMonitor realMonitor;

		NoProgressMonitor(TaskMonitor realMonitor) {
			this.realMonitor = realMonitor;
		}

		@Override
		public void incrementProgress(long incrementAmount) {
			// no!
		}

		@Override
		public void cancel() {
			super.cancel();
			realMonitor.cancel();
		}
	}
}
