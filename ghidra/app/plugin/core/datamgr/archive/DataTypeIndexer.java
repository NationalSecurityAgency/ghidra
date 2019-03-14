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
package ghidra.app.plugin.core.datamgr.archive;

import java.util.*;

import javax.swing.SwingUtilities;

import ghidra.app.plugin.core.datamgr.util.DataTypeComparator;
import ghidra.program.model.data.*;
import ghidra.util.task.*;

/**
 * A class that stores a sorted list of all the {@link DataType} objects in the current data type
 * manager plugin.  This class does its work lazily such that no work is done until
 * {@link #getSortedDataTypeList()} is called.  Even when that method is called no work will be
 * done if the state of the data types in the system hasn't changed.
 */
public class DataTypeIndexer {
	private List<DataTypeManager> dataTypeManagers = new ArrayList<>();
	private List<DataType> dataTypeList = Collections.emptyList();
	private Comparator<DataType> dataTypeComparator = new DataTypeComparator();
	private DataTypeIndexUpdateListener listener = new DataTypeIndexUpdateListener();

	private volatile boolean isStale = true;

	// Note: synchronizing here prevents concurrent mod issues with the managers list
	public synchronized void addDataTypeManager(DataTypeManager dataTypeManager) {
		if (!dataTypeManagers.contains(dataTypeManager)) {
			dataTypeManager.addDataTypeManagerListener(listener);
			dataTypeManager.addInvalidatedListener(listener);
			dataTypeManagers.add(dataTypeManager);
			markStale();
		}
	}

	// Note: synchronizing here prevents concurrent mod issues with the managers list
	public synchronized void removeDataTypeManager(DataTypeManager dataTypeManager) {
		if (dataTypeManagers.contains(dataTypeManager)) {
			dataTypeManager.removeDataTypeManagerListener(listener);
			dataTypeManager.removeInvalidatedListener(listener);
			dataTypeManagers.remove(dataTypeManager);
			markStale();
		}
	}

	/**
	 * Returns a sorted list of the data types open in the current tool.  The sorting of the list
	 * is done using the {@link DataTypeComparator}.
	 *
	 * @return a sorted list of the data types open in the current tool.
	 */
	public synchronized List<DataType> getSortedDataTypeList() {

		List<DataType> newList = updateDataTypeList();

		if (isStale) {
			//
			// 					Unusual Code Alert!
			// Don't save the list we just made, as it is already stale again due to changes
			// to the Data Type Managers that happened while we were building.
			//
			return newList;
		}

		dataTypeList = newList;
		return Collections.unmodifiableList(newList);
	}

	private List<DataType> updateDataTypeList() {
		if (!isStale) {
			return dataTypeList;
		}

		// set the flag here to handle the case where changes are made while we are building
		isStale = false;

		IndexerTask task = new IndexerTask();
		if (SwingUtilities.isEventDispatchThread()) {
			TaskLauncher.launch(task);
		}
		else {
			task.run(TaskMonitor.DUMMY);
		}

		List<DataType> newList = task.getList();
		return newList;
	}

	// Note: purposefully not synchronized for speed
	private void markStale() {
		isStale = true;

		// Deleting this when stale allows us to free the memory.  This is useful, since it
		// is possible that once marked stale, we may never have another request for this data
		// again.
		dataTypeList = Collections.emptyList();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class IndexerTask extends Task {

		private List<DataType> list = new ArrayList<>();

		IndexerTask() {
			super("Data Type Indexer Task", false, true, true);
		}

		@Override
		public void run(TaskMonitor monitor) {

			monitor.initialize(dataTypeManagers.size());
			monitor.setMessage("Preparing to index data types...");

			Iterator<DataTypeManager> iterator = dataTypeManagers.iterator();
			while (iterator.hasNext()) {
				DataTypeManager dataTypeManager = iterator.next();

				monitor.setMessage("Searching " + dataTypeManager.getName());
				dataTypeManager.getAllDataTypes(list);
				monitor.incrementProgress(1);
			}

			Collections.sort(list, dataTypeComparator);
		}

		List<DataType> getList() {
			return list;
		}
	}

	private class DataTypeIndexUpdateListener
			implements DataTypeManagerChangeListener, InvalidatedListener {
		@Override
		public void dataTypeManagerInvalidated(DataTypeManager dataTypeManager) {
			markStale();
		}

		@Override
		public void categoryAdded(DataTypeManager dtm, CategoryPath path) {
			markStale();
		}

		@Override
		public void categoryMoved(DataTypeManager dtm, CategoryPath oldPath, CategoryPath newPath) {
			markStale();
		}

		@Override
		public void categoryRemoved(DataTypeManager dtm, CategoryPath path) {
			markStale();
		}

		@Override
		public void categoryRenamed(DataTypeManager dtm, CategoryPath oldPath,
				CategoryPath newPath) {
			markStale();
		}

		@Override
		public void dataTypeAdded(DataTypeManager dtm, DataTypePath path) {
			markStale();
		}

		@Override
		public void dataTypeChanged(DataTypeManager dtm, DataTypePath path) {
			markStale();
		}

		@Override
		public void dataTypeMoved(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath) {
			markStale();
		}

		@Override
		public void dataTypeRemoved(DataTypeManager dtm, DataTypePath path) {
			markStale();
		}

		@Override
		public void dataTypeRenamed(DataTypeManager dtm, DataTypePath oldPath,
				DataTypePath newPath) {
			markStale();
		}

		@Override
		public void dataTypeReplaced(DataTypeManager dtm, DataTypePath oldPath,
				DataTypePath newPath, DataType newDataType) {
			markStale();
		}

		@Override
		public void favoritesChanged(DataTypeManager dtm, DataTypePath path, boolean isFavorite) {
			// don't care
		}

		@Override
		public void sourceArchiveAdded(DataTypeManager dtm, SourceArchive dataTypeSource) {
			markStale();
		}

		@Override
		public void sourceArchiveChanged(DataTypeManager dtm, SourceArchive dataTypeSource) {
			markStale();
		}
	}
}
