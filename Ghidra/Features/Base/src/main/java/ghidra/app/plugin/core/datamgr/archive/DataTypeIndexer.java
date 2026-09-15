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

import ghidra.program.model.data.*;
import ghidra.util.Swing;
import ghidra.util.task.*;

/**
 * A class that stores a sorted list of all the {@link DataType} and a list of all the 
 * {@link CategoryPath} objects in the current data type manager plugin.  This class does its work 
 * lazily such that no work is done until {@link #getSortedDataTypeList()} is called. Even when that
 * method is called no work will be done if the state of the data types in the system hasn't 
 * changed.
 */
public class DataTypeIndexer {

	private static final DataCache EMPTY_CACHE =
		new DataCache(Collections.emptyList(), Collections.emptyList());
	private volatile boolean isStale = true;
	private volatile DataCache dataCache;

	private List<DataTypeManager> dataTypeManagers = new ArrayList<>();
	private DataTypeIndexUpdateListener listener = new DataTypeIndexUpdateListener();

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
	 * is done using the {@link DataTypeComparator} whose primary sort is based upon the 
	 * {@link DataTypeNameComparator}.
	 *
	 * @return a sorted list of the data types open in the current tool.
	 */
	public synchronized List<DataType> getSortedDataTypeList() {
		DataCache currentCache = updateDataCache();
		return currentCache.dataTypes();
	}

	/**
	 * Returns a list of the unique Category Paths ({@link CategoryPath}) as utilized by the 
	 * data types open in the current tool.  
	 * 
	 * @return a list of the {@link CategoryPath} associated with the data types open in the 
	 * current tool.
	 */
	public synchronized List<CategoryPath> getSortedCategoryPathList() {
		DataCache currentCache = updateDataCache();
		return currentCache.categories();
	}

	private synchronized DataCache updateDataCache() {

		/*
		 	This method is super complicated due to the fact that our cache can be invalidated in a
		 	non-synchronized call.  This method is synchronized to prevent multiple external clients
		 	from triggering a data load when the cache is stale.  However, system events may 
		 	invalidate the cache while we are in the process of getting new data.  We let those 
		 	events clear the cache outside of a synchronized block to avoid blocking the swing 
		 	thread.  
		 */
		DataCache currentCache = dataCache;
		if (!isStale) {
			return currentCache; // the current cache is not stale; no need to rebuild
		}

		// mark as not stale (this can be changed at any time from external events)
		isStale = false;

		IndexerTask task = new IndexerTask();
		if (Swing.isSwingThread()) {
			TaskLauncher.launch(task);
		}
		else {
			task.run(TaskMonitor.DUMMY);
		}

		// Store the new results, but check below to see if they were marked as stale while working.
		// Either way, we will return these new results below.
		DataCache newCache = new DataCache(task.getDataTypes(), task.getCategoryPaths());
		dataCache = newCache;

		if (isStale) {
			// There is a chance, while we were working, the cache was marked as stale.  Assign the
			// new cache and then clear it here if we hit that case.  The results we return below
			// will be valid for the client for this call only.
			// Note: we have guilty knowledge of the markStale() method, which sets the flag first
			//       and then clears the cache.
			dataCache = EMPTY_CACHE;
		}

		return newCache;
	}

	// Note: intentionally not synchronized for speed; called from system events
	private void markStale() {
		isStale = true;

		// Deleting this when stale allows us to free the memory.  This is useful, since it is 
		// possible that once marked stale, we may never have another request for this data again.
		dataCache = EMPTY_CACHE;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private record DataCache(List<DataType> dataTypes, List<CategoryPath> categories) {

	}

	// We use a case-insensitive sort on the data since clients may perform case-insensitive 
	// searches.  This class was using the DataTypeComparator.INSTANCE for sorting, which is 
	// case-sensitive.  This produced cases where not all matching data were found during queries, 
	// which depended on how the binary search traversed the list.  If there is a reason to use that
	// comparator over this one, then we need to re-think how this list is sorted.
	private class CaseInsensitiveDataTypeComparator implements Comparator<DataType> {

		@Override
		public int compare(DataType dt1, DataType dt2) {
			String name1 = dt1.getName();
			String name2 = dt2.getName();

			int result = name1.compareToIgnoreCase(name2);
			if (result != 0) {
				return result;
			}

			result = name1.compareTo(name2);
			if (result != 0) {
				// let equivalent names be sorted by case ('-' for lower-case first)
				return -result;
			}

			// if the names are the same, then sort by data type manager
			String dtmName1 = dt1.getDataTypeManager().getName();
			String dtmName2 = dt2.getDataTypeManager().getName();
			result = dtmName1.compareToIgnoreCase(dtmName2);
			if (result != 0) {
				return result;
			}

			// if they have the same name, and are in the same DTM, then compare paths
			CategoryPath cp1 = dt1.getCategoryPath();
			CategoryPath cp2 = dt2.getCategoryPath();
			String p1 = cp1.getPath();
			String p2 = cp2.getPath();
			return p1.compareToIgnoreCase(p2);
		}
	}

	private class CaseInsensitiveCategoryComparator implements Comparator<CategoryPath> {

		@Override
		public int compare(CategoryPath cp1, CategoryPath cp2) {

			String name1 = cp1.getName();
			String name2 = cp2.getName();

			int result = name1.compareToIgnoreCase(name2);
			if (result != 0) {
				return result;
			}

			result = name1.compareTo(name2);
			if (result != 0) {
				// let equivalent names be sorted by case ('-' for lower-case first)
				return -result;
			}

			// if the names are the same, then sort by full path
			String p1 = cp1.getPath();
			String p2 = cp2.getPath();
			return p1.compareToIgnoreCase(p2);
		}
	}

	private class IndexerTask extends Task {

		private List<DataType> dataTypes = new ArrayList<>();
		private List<CategoryPath> categories = new ArrayList<>();
		private Set<CategoryPath> categorySet = new HashSet<>();

		IndexerTask() {
			super("Data Type Indexer Task", false, true, true);
		}

		@Override
		public void run(TaskMonitor monitor) {

			monitor.initialize(dataTypeManagers.size());
			monitor.setMessage("Preparing to index data types...");

			for (DataTypeManager dtm : dataTypeManagers) {
				monitor.setMessage("Searching " + dtm.getName());
				dtm.getAllDataTypes(dataTypes);

				Category root = dtm.getRootCategory();
				populateCategories(root);

				monitor.incrementProgress(1);
			}

			Collections.sort(dataTypes, new CaseInsensitiveDataTypeComparator());

			categories.addAll(categorySet);
			Collections.sort(categories, new CaseInsensitiveCategoryComparator());
		}

		private void populateCategories(Category parent) {

			categorySet.add(parent.getCategoryPath());
			Category[] children = parent.getCategories();
			for (Category category : children) {
				CategoryPath path = category.getCategoryPath();
				categorySet.add(path);

				populateCategories(category);
			}
		}

		List<DataType> getDataTypes() {
			return dataTypes;
		}

		List<CategoryPath> getCategoryPaths() {
			return categories;
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

		@Override
		public void programArchitectureChanged(DataTypeManager dataTypeManager) {
			markStale();
		}

		@Override
		public void restored(DataTypeManager dataTypeManager) {
			markStale();
		}
	}

}
