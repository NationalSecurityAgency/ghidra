/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.datamgr;

import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

/**
 * Manages the attributes for data types; used by the manage data types
 * dialog to populate the data types tree structure.
 */
public class DataTypePropertyManager {

	private WeakSet<ChangeListener> changeListeners =
		WeakDataStructureFactory.createCopyOnReadWeakSet();
	private KeyStroke recentlyUsedKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_Y, 0);
	private DataType recentlyUsedDataType;
	private long recentlyUsedDtId;

	private DataTypeManager programDataTypesManager;

	/**
	 * Data type was removed, so remove it is no longer a recently used.
	 */
	void remove(DataType dt) {
		boolean notify = false;
		if (isRecentlyUsedDataType(dt)) {
			recentlyUsedDataType = null;
			notify = true;
		}
		if (notify) {
			notifyListeners();
		}
	}

	void dataTypeRenamed(DataType dt) {
		if (isFavorite(dt) || isRecentlyUsedDataType(dt)) {
			notifyListeners();
		}
	}

	private boolean isRecentlyUsedDataType(DataType dataType) {
		return (recentlyUsedDataType != null && recentlyUsedDataType.equals(dataType));
	}

	private boolean isFavorite(DataType dt) {
		return dt.getDataTypeManager().isFavorite(dt);
	}

	/**
	 * Sets the given data type to be the recently used data type.  
	 * @return true if the data type was added; false if the data type
	 * is already in the recently used list
	 */
	boolean setRecentlyUsed(DataType dt) {
		if (dt != recentlyUsedDataType && !dt.isDeleted()) {
			recentlyUsedDataType = dt;
			if (programDataTypesManager != null &&
				dt.getDataTypeManager() == programDataTypesManager) {
				recentlyUsedDtId = programDataTypesManager.getID(dt);
			}
			return true;
		}
		return false;
	}

	/**
	 * Get the data type that was most recently used.
	 */
	DataType getRecentlyUsed() {
		return recentlyUsedDataType;
	}

	/**
	 * Get the KeyStroke for the most recently used.
	 */
	KeyStroke getKeyStrokeForRecentlyUsed() {
		return recentlyUsedKeyStroke;
	}

	void programOpened(Program program) {
		programDataTypesManager = program.getListing().getDataTypeManager();
	}

	void programClosed(Program program) {
		recentlyUsedDataType = null;
		programDataTypesManager = null;
	}

	void domainObjectRestored(DataTypeManagerDomainObject domainObject) {
		DataTypeManager dataTypeManager = domainObject.getDataTypeManager();
		if (dataTypeManager != programDataTypesManager) {
			return; // Ignore since not our program data type manager.
		}
		if (recentlyUsedDataType != null &&
			recentlyUsedDataType.getDataTypeManager() == programDataTypesManager) {
			recentlyUsedDataType = programDataTypesManager.getDataType(recentlyUsedDtId);
		}

		notifyListeners();
	}

//==================================================================================================
// Listeners
//==================================================================================================
	/**
	 * Add listener that is notified if favorites list changes.
	 * <STRONG>WARNING:</STRONG>The implementation for the listeners uses weak
	 * references so that when listeners go away, no handle is kept for them
	 * in the list of listeners. Therefore, the class that creates the
	 * change listener must keep a handle to it so that some object keeps
	 * a handle; otherwise, the change listener will be garbage collected
	 * and the listener never gets calls.
	 */
	public void addChangeListener(ChangeListener l) {
		changeListeners.add(l);
	}

	/**
	 * Remove the listener.
	 */
	public void removeChangeListener(ChangeListener l) {
		changeListeners.remove(l);
	}

	/**
	 * Notify listeners that the favorites list changed.
	 */
	private void notifyListeners() {
		if (changeListeners.isEmpty()) {
			return;
		}

		Runnable notifyRunnable = new Runnable() {
			@Override
			public void run() {
				ChangeEvent event = new ChangeEvent(DataTypePropertyManager.this);
				for (ChangeListener l : changeListeners) {
					l.stateChanged(event);
				}
			}
		};

		SystemUtilities.runSwingNow(notifyRunnable);
	}
}
