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
package docking.widgets.table.threaded;

import static docking.widgets.table.AddRemoveListItem.Type.*;

import java.util.*;

import javax.swing.SwingUtilities;
import javax.swing.event.TableModelEvent;

import docking.widgets.table.*;
import docking.widgets.table.sort.DefaultColumnComparator;
import generic.concurrent.ConcurrentListenerSet;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.Swing;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.worker.Worker;

/**
 * The base implementation of the threaded table model.
 * <p>
 * You can optionally set this model to load data incrementally by passing the correct
 * constructor argument.  Note, if you make this model incremental, then you need to set an
 * incremental task monitor in order to get feedback about loading
 * (see {@link #setIncrementalTaskMonitor(TaskMonitor)}.  Alternatively, you can use
 * a {@link GThreadedTablePanel}, which will install the proper monitor for you.
 *
 * @param <ROW_OBJECT> the row object class for this table model.
 * @param <DATA_SOURCE> the type of data that will be returned from {@link #getDataSource()}.  This
 *                    object will be given to the {@link DynamicTableColumn} objects used by this
 *                    table model when
 *                    {@link DynamicTableColumn#getValue(Object, ghidra.docking.settings.Settings, Object, ServiceProvider)}
 *                    is called.
 */
public abstract class ThreadedTableModel<ROW_OBJECT, DATA_SOURCE>
		extends GDynamicColumnTableModel<ROW_OBJECT, DATA_SOURCE>
		implements RowObjectFilterModel<ROW_OBJECT> {

	private ThreadedTableModelUpdateMgr<ROW_OBJECT> updateManager;
	private boolean loadIncrementally;
	private TaskMonitor incrementalMonitor = TaskMonitor.DUMMY;
	private ConcurrentListenerSet<ThreadedTableModelListener> listeners =
		new ConcurrentListenerSet<>();

	private String modelName;
	protected TableData<ROW_OBJECT> allData = TableData.createEmptyDataset();
	protected TableData<ROW_OBJECT> filteredData =
		TableData.createSubDataset(allData, new ArrayList<ROW_OBJECT>(), null);

	//
	// These data state values (sort/filter states) can be changed by the user while the
	// table is processing updates.  So, we keep a copy of these values here, as opposed to
	// storing them in the TableData object.  The values in those object represent how that data
	// was prepared, whereas these values here may represent pending changes that have not been
	// applied.
	//
	private volatile TableSortingContext<ROW_OBJECT> pendingSortContext;

	/**
	 * This variable can be in one of three states:
	 * 	<ul>
	 * 		<li>null - signals that there is no filter change taking place</li>
	 * 		<li>An instance of <code>NullTableFilter</code> - the client has removed the current
	 *          filter by calling {@link #setTableFilter(TableFilter)} with a null value</li>
	 * 		<li>An instance of a custom <code>TableFilter</code> - the client has changed the
	 *          filter to a non-null value by calling {@link #setTableFilter(TableFilter)}</li>
	 *  </ul>
	 */
	private volatile TableFilter<ROW_OBJECT> pendingTableFilter;
	private TableFilter<ROW_OBJECT> tableFilter = new NullTableFilter<>();

	private ThreadLocal<Map<ROW_OBJECT, Map<Integer, Object>>> threadLocalColumnCache =
		new ThreadLocal<>();

	private volatile Worker worker; // only created as needed (if we are incremental)
	private int minUpdateDelayMillis;
	private int maxUpdateDelayMillis;
	private TableAddRemoveStrategy<ROW_OBJECT> binarySearchAddRemoveStrategy =
		new DefaultAddRemoveStrategy<>();

	protected ThreadedTableModel(String modelName, ServiceProvider serviceProvider) {
		this(modelName, serviceProvider, null);
	}

	protected ThreadedTableModel(String modelName, ServiceProvider serviceProvider,
			TaskMonitor monitor) {
		this(modelName, serviceProvider, monitor, false);
	}

	/**
	 * The constructor through which all others pass.
	 * <p>
	 * This class must be created on the Swing Thread
	 * (see {@link SwingUtilities#isEventDispatchThread()}).
	 *
	 * @param modelName The name of the table model. This value will appear as the name of the
	 *                  thread that manipulates the table data.
	 * @param serviceProvider The service provider of the environment.  This will be used to
	 *                        allow column objects to have access to services.  This man not be
	 *                        null.
	 * @param monitor The task monitor to use when manipulating table data (i.e., loading, sorting,
	 *                filtering).
	 * @param loadIncrementally When true, the table's results will be displayed as they are
	 *                          loaded; when false, the table's results will be displayed after
	 *                          all items have been loaded.  Passing true is helpful for models
	 *                          that take a long time to run and periodically find data.
	 *                          Alternatively, for quick loading tables, the overhead of loading
	 *                          incrementally is wasteful.
	 */
	protected ThreadedTableModel(String modelName, ServiceProvider serviceProvider,
			TaskMonitor monitor, boolean loadIncrementally) {
		super(serviceProvider);

		if (!Swing.isSwingThread()) {
			throw new AssertException(
				"You must create the ThreadedTableModel in the AWT Event Dispatch Thread");
		}

		this.modelName = modelName;
		this.loadIncrementally = loadIncrementally;

		updateManager = new ThreadedTableModelUpdateMgr<>(this, monitor);

		if (loadIncrementally) {
			updateManager.addThreadedTableListener(new IncrementalUpdateManagerListener());
		}
		else {
			updateManager.addThreadedTableListener(new NonIncrementalUpdateManagerListener());
		}

		// We are expecting to be in the swing thread.  We want the reload to happen after our
		// constructor is fully completed since the reload will cause our initialize method to
		// be called in another thread, thereby creating a possible race condition.
		Swing.runLater(() -> updateManager.reload());
	}

	public boolean isLoadIncrementally() {
		return loadIncrementally;
	}

	@Override
	protected void initializeSorting() {
		// we do nothing here since our sorting is handled by our update manager
	}

	/**
	 * A package-level method.  Subclasses should not call this.
	 * 
	 * <p>This exists to handle whether this model should load incrementally.
	 * 
	 * @param monitor the monitor
	 * @return the loaded data
	 * @throws CancelledException if the load was cancelled
	 */
	final List<ROW_OBJECT> load(TaskMonitor monitor) throws CancelledException {
		if (loadIncrementally) {
			// do the load later, incrementally
			initializeWorker();
			scheduleIncrementalLoad();
			return Collections.emptyList(); // data will be updated later
		}

		// do the load now
		ListAccumulator<ROW_OBJECT> accumulator = new ListAccumulator<>();
		doLoad(accumulator, monitor);
		return accumulator.asList();
	}

	private void initializeWorker() {
		if (worker == null) {
			worker = new Worker("GTable Worker: " + getName(), incrementalMonitor);
		}

		cancelCurrentWorkerJob();
		worker.waitUntilNoJobsScheduled(Integer.MAX_VALUE);
	}

	private void cancelCurrentWorkerJob() {
		if (worker != null && worker.isBusy()) {
			worker.clearAllJobsWithInterrupt_IKnowTheRisks();
		}
	}

	private void scheduleIncrementalLoad() {
		worker.schedule(createIncrementalLoadJob());
	}

	protected IncrementalLoadJob<ROW_OBJECT> createIncrementalLoadJob() {
		return new IncrementalLoadJob<>(this, new IncrementalLoadJobListener());
	}

	/**
	 * The basic method that all children must implement.  This is where children load their
	 * data.
	 * @param accumulator the datastructure into which you should incrementally place you table
	 *        row data
	 * @param monitor the task monitor to check for cancellations and to update progress
	 *
	 * @throws CancelledException if the task monitor has been cancelled and a call is made
	 *         to <code>monitor.checkCancelled();</code>.
	 */
	protected abstract void doLoad(Accumulator<ROW_OBJECT> accumulator, TaskMonitor monitor)
			throws CancelledException;

	/**
	 * This method will retrieve a column value for the given row object.  Further, the retrieved
	 * value will be cached.   This is useful when sorting a table, as the same column value may
	 * be requested multiple times.
	 * 
	 * <p><u>Performance Notes</u>
	 * <ul>
	 * 	<li>This method uses a {@link HashMap} to cache column values for a row object.   Further,
	 *      upon a key collision, the map will perform O(logn) lookups <b>if the 
	 *      key (the row object) is {@link Comparable}</b>.   If the key is not comparable, then
	 *      the collision lookups will be linear.    So, make your row objects comparable
	 *      for maximum speed <b>when your table size becomes large</b>  (for small tables there
	 *      is no observable impact).
	 *  <li>Even if your row objects are comparable, relying on this table model to convert your 
	 *      row object into column values can be slow <b>for large tables</b>.  This is because
	 *      the default column comparison framework for the tables will call this method 
	 *      multiple times, resulting in many more method calls per column value lookup.  For 
	 *      large data, the repeated method calls start to become noticeable.  For maximum 
	 *      column sorting speed, use a comparator that works not on the column value, but on 
	 *      the row value.  To do this, return a comparator from your model's 
	 *      {@link #createSortComparator(int)} method, instead of from the column itself or 
	 *      by relying on column item implementing {@link Comparable}.  This is possible any
	 *      time that a row object already has a field that is used for a given column.
	 * </ul>
	 * 
	 * @param rowObject the row object
	 * @param columnIndex the column index for which to get a value
	 * @return the column value
	 */
	Object getCachedColumnValueForRow(ROW_OBJECT rowObject, int columnIndex) {

		Map<ROW_OBJECT, Map<Integer, Object>> cachedColumnValues = threadLocalColumnCache.get();

		if (cachedColumnValues == null) {
			// the caching has not been enabled--this must be a simple lookup from a client
			// that cares not about speed
			return getColumnValueForRow(rowObject, columnIndex);
		}

		Map<Integer, Object> columnMap = cachedColumnValues.get(rowObject);
		if (columnMap == null) {
			columnMap = new HashMap<>();
			cachedColumnValues.put(rowObject, columnMap);
		}

		Object columnValueForRow = columnMap.get(columnIndex);
		if (columnValueForRow == null) {
			columnValueForRow = getColumnValueForRow(rowObject, columnIndex);
			columnMap.put(columnIndex, columnValueForRow);
		}

		return columnValueForRow;
	}

	void initializeCache() {
		threadLocalColumnCache.set(new LRUMap<ROW_OBJECT, Map<Integer, Object>>(1000000));
	}

	void clearCache() {
		Map<ROW_OBJECT, Map<Integer, Object>> cachedColumnValues = threadLocalColumnCache.get();
		cachedColumnValues.clear();
		threadLocalColumnCache.set(null);
	}

	@Override
	public List<ROW_OBJECT> getModelData() {
		return Collections.unmodifiableList(filteredData.getData());
	}

	@Override
	public List<ROW_OBJECT> getUnfilteredData() {
		return Collections.unmodifiableList(allData.getData());
	}

	/**
	 * Performs a quick search for the given item in the <b>unfiltered</b> data of this model.
	 * To search only for object that are visible in the GUI, use
	 * {@link #getIndexForRowObject(Object)}.
	 *
	 * @param rowObject The object for which to search
	 * @return The index for the given object; a negative value if the object is not in the list
	 * @see #getIndexForRowObject(Object)
	 */
	protected int getUnfilteredIndexForRowObject(ROW_OBJECT rowObject) {
		return getIndexForRowObject(rowObject, getUnfilteredData());
	}

	/**
	 * Returns the row object at the given index in the <b>unfiltered data</b> of this model;
	 * null if the index is negative or larger than the list.  To search only for object
	 * that are visible in the GUI, use {@link #getRowObject(int)}.
	 *
	 * @param row The row index for which to get a row object
	 * @return Returns the row object at the given index in the <b>unfiltered data</b> of this model;
	 *         null if the index is negative or larger than the list.
	 * @see #getRowObject(int)
	 */
	protected ROW_OBJECT getUnfilteredRowObjectForIndex(int row) {
		List<ROW_OBJECT> unfilteredData = getUnfilteredData();
		if (row < 0 || row >= unfilteredData.size()) {
			return null;
		}
		return unfilteredData.get(row);
	}

	@Override
	protected Comparator<ROW_OBJECT> createSortComparator(int columnIndex) {

		Comparator<Object> columnComparator = createSortComparatorForColumn(columnIndex);
		if (columnComparator != null) {
			// the given column has its own comparator; wrap and us that
			return new ThreadedTableColumnComparator<>(this, columnIndex, columnComparator);
		}

		return new ThreadedTableColumnComparator<>(this, columnIndex, new DefaultColumnComparator(),
			new ThreadedBackupRowComparator<>(this, columnIndex));
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		try {
			return super.getValueAt(rowIndex, columnIndex);
		}
		catch (RuntimeException e) {
			if (!(e.getCause() instanceof ClosedException)) {
				// Ignore database closure which could occur, since we are threaded
				throw e;
			}
		}
		return null;
	}

	@Override
	protected void sort(List<ROW_OBJECT> data,
			TableSortingContext<ROW_OBJECT> tableSortingContext) {
		if (data.isEmpty() && !updateManager.isBusy()) {
			// Unusual Code Alert!:
			// Empty data implies we may have been cancelled before any data was loaded.  Therefore,
			// we must trigger a new load of data before we can sort.  Loading data will trigger a
			// sort, and we want to use the new sorting data we've just been given.  By calling
			// sortCompleted() here, we are making sure that the follow-on sort will use this
			// new sort data.
			sortCompleted(tableSortingContext);
			updateManager.reload();
			return;
		}

		pendingSortContext = tableSortingContext;
		updateManager.sort(tableSortingContext, false);
	}

	/**
	 * Returns the current sorting context, which is the next one to be applied, if a sort is
	 * pending; otherwise the current sorting context.
	 * @return the sort context
	 */
	TableSortingContext<ROW_OBJECT> getSortingContext() {
		if (pendingSortContext != null) {
			return pendingSortContext;
		}

		return createSortingContext(getTableSortState());
	}

	/**
	 * Returns the filter for this model.  The value returned from this method will not be null,
	 * but will instead be an instanceof {@link NullTableFilter} when no filter is applied.   The
	 * value returned from this method may not actually yet be applied, depending upon when the
	 * background thread finishes loading.
	 *
	 * @return the filter
	 */
	@Override
	public TableFilter<ROW_OBJECT> getTableFilter() {
		if (pendingTableFilter != null) {
			return pendingTableFilter;
		}
		return tableFilter;
	}

	/**
	 * Returns true if there is a table filter set that is not the {@link NullTableFilter}.
	 *
	 * @return true if there is a table filter set.
	 */
	public boolean hasFilter() {
		TableFilter<ROW_OBJECT> currentFilter = getTableFilter();
		return !currentFilter.isEmpty();
	}

	/**
	 * Override this to change how filtering is performed.  This implementation will do nothing
	 * if a <code>TableFilter</code> has not been set via a call to {@link #setTableFilter(TableFilter)}.
	 * 
	 *
	 * @param data The list of data to be filtered.
	 *
	 * @param monitor the progress monitor to check for cancellation.
	 * @param lastSortingContext the comparator used to sort data.  This can be used by overridden
	 *                   filter methods that need to query data about how the table is sorted.
	 * @return The <b>new</b> filtered list of data.  If no filtering takes place, then the
	 * 	       original list should be returned.
	 * @throws CancelledException If the filter operation is cancelled.
	 */
	protected List<ROW_OBJECT> doFilter(List<ROW_OBJECT> data,
			TableSortingContext<ROW_OBJECT> lastSortingContext, TaskMonitor monitor)
			throws CancelledException {

		// copy the filter so that it is not changed by another thread whilst this filter is
		// taking place

		if (data.size() == 0) {
			return data;
		}

		if (!hasFilter()) {
			return data;
		}

		monitor.initialize(data.size());

		TableFilter<ROW_OBJECT> filterCopy = getTableFilter();
		List<ROW_OBJECT> filteredList = new ArrayList<>();
		for (int row = 0; row < data.size(); row++) {
			if (monitor.isCancelled()) {
				return filteredList; // cancelled just return what has matches so far
			}

			ROW_OBJECT rowObject = data.get(row);
			if (filterCopy.acceptsRow(rowObject)) {
				filteredList.add(rowObject);
			}
			monitor.incrementProgress(1);
		}

		return filteredList;
	}

	@Override
	public int getUnfilteredRowCount() {
		return allData.size();
	}

	@Override
	public boolean isFiltered() {
		return filteredData.size() != allData.size();
	}

	/**
	 * Sets the given <code>TableFilter</code> on this model.  This table filter will then be used
	 * by this model in the default {@link #doFilter(List, TableSortingContext, TaskMonitor)}
	 * method.
	 * @param tableFilter The filter to use for table filtering.
	 */
	@Override
	public void setTableFilter(TableFilter<ROW_OBJECT> tableFilter) {
		this.pendingTableFilter = tableFilter;
		if (pendingTableFilter == null) {
			// Don't allow the pending filter to be null in this case.  The client has changed
			// the filter.  If we use null, then we don't know the difference between a client
			// change request or a simple refilter operation.
			pendingTableFilter = new NullTableFilter<>();
		}
		reFilter();
	}

	private void setAppliedTableFilter(TableFilter<ROW_OBJECT> tableFilter) {
		if (tableFilter == null) {
			// null means there was no change to the text filter--so don't set it (see the
			// javadoc for the filter variables)
			return;
		}

		this.tableFilter = pendingTableFilter;
		this.pendingTableFilter = null;
	}

	/**
	 * Schedules an update for the specified object.
	 * @param obj the object for which to schedule the update
	 */
	public void updateObject(ROW_OBJECT obj) {
		updateManager.addRemove(new AddRemoveListItem<>(CHANGE, obj));
	}

	/**
	 * Adds the specified object to this model and schedules an update.
	 * @param obj the object to add
	 */
	public void addObject(ROW_OBJECT obj) {
		updateManager.addRemove(new AddRemoveListItem<>(ADD, obj));
	}

	/**
	 * Removes the specified object from this model and schedules an update.
	 * 
	 * <P>Note: for this method to function correctly, the given object must compare as 
	 * {@link #equals(Object)} and have the same {@link #hashCode()} as the object to be removed 
	 * from the table data.   This allows clients to create proxy objects to pass into this method,
	 * as long as they honor those requirements.    
	 * 
	 * <P>If this model's data is sorted, then a binary search will be used to locate the item
	 * to be removed.  However, for this to work, all field used to sort the data must still be 
	 * available from the original object and must be the same values.   If this is not true, then
	 * the binary search will not work and a brute force search will be used.
	 * 
	 * @param obj the object to remove
	 */
	public void removeObject(ROW_OBJECT obj) {
		updateManager.addRemove(new AddRemoveListItem<>(REMOVE, obj));
	}

	protected void updateNow() {
		updateManager.updateNow();
	}

	protected void setModelState(TableData<ROW_OBJECT> allData,
			TableData<ROW_OBJECT> filteredData) {

		SystemUtilities.assertThisIsTheSwingThread("Must be called on the Swing thread");

		//@formatter:off
		// The data is changed when it is filtered OR when an item has been added or removed
		boolean dataChanged = this.filteredData.getId() != filteredData.getId() || 
							  this.filteredData.size() != filteredData.size();
		//@formatter:on
		this.allData = allData;
		this.filteredData = filteredData;

		setAppliedTableFilter(pendingTableFilter);
		pendingSortContext = null;

		TableSortingContext<ROW_OBJECT> newSortingContext = filteredData.getSortContext();
		if (newSortingContext != null) {
			sortCompleted(newSortingContext);
		}

		notifyModelSorted(dataChanged);
	}

	TableData<ROW_OBJECT> getAllTableData() {
		return allData;
	}

	TableData<ROW_OBJECT> getCurrentTableData() {
		return filteredData;
	}

	protected List<ROW_OBJECT> getAllData() {
		return new ArrayList<>(allData.getData());
	}

	/**
	 * Returns true if the model is busy. "Busy" means the model
	 * is either loading or updating.
	 * @return true if the model is busy
	 */
	public boolean isBusy() {
		return updateManager.isBusy() || isWorkerBusy();
	}

	/**
	 * Returns whether this table is loading, which is somewhat misleading.
	 * <p>
	 * If this table model is an incrementally loading table model, then this method returns true
	 * only when an incremental load is taking place.  Otherwise, this method returns true
	 * whenever the update manager is busy, which may be a load operation, or just a sort
	 * operation.  At issue is the fact that unless we are an incrementally loading model, we
	 * cannot tell if we are actually loading, or just busy otherwise manipulating out data.
	 *
	 * @return whether this table is loading, which is somewhat misleading.
	 */
	boolean isLoading() {
		if (loadIncrementally) {
			return isWorkerBusy();
		}
		return updateManager.isBusy();
	}

	private boolean isWorkerBusy() {
		return worker != null && worker.isBusy();
	}

	/**
	 * Resort the table using the current sort criteria.  This is useful if the data in the
	 * table has changed and is no longer sorted properly.  If the setSort method is used, nothing
	 * will happen because the table will think it is already sorted on that criteria.
	 */
	@Override
	public void reSort() {
		updateManager.sort(getSortingContext(), true);
	}

	/**
	 * Triggers this class to filter the contents of the data.
	 */
	public void reFilter() {
		updateManager.filter();
	}

	/**
	 * Schedules the model to completely reload
	 * its underlying data.
	 */
	public void reload() {
		cancelCurrentWorkerJob();
		updateManager.reload();
	}

	/**
	 * @see javax.swing.table.AbstractTableModel#fireTableChanged(javax.swing.event.TableModelEvent)
	 */
	@Override
	public void fireTableChanged(TableModelEvent e) {
		if (Swing.isSwingThread()) {
			super.fireTableChanged(e);
			return;
		}
		Swing.runLater(() -> ThreadedTableModel.super.fireTableChanged(e));
	}

	/**
	 * Disposes this model.
	 * Once a model has been disposed, it cannot be reused.
	 */
	@Override
	public void dispose() {
		updateManager.dispose();
		if (worker != null) {
			worker.dispose();
		}
		doClearData();
		disposeDynamicColumnData();
	}

	/**
	 * This method will clear all data and trigger fire a table data changed.  Use this method to
	 * immediately clear all data.  This is useful when you want to reload your table data and
	 * not have any old data hanging around being painted, which can produce odd results.
	 */
	protected void clearData() {
		doClearData();
		fireTableDataChanged();
	}

	private void doClearData() {
		cancelAllUpdates();
		getLastSelectedObjects().clear(); // when our data is cleared, so is our saved selection!
		allData.clear();
		filteredData = allData;
	}

	/**
	 * Cancels all current and pending updates to the model. Waits until all updates have
	 * been cancelled.
	 */
	public void cancelAllUpdates() {
		if (worker != null) {
			worker.clearAllJobsWithInterrupt_IKnowTheRisks();
		}
		updateManager.cancelAllJobs();
	}

	/**
	 * @see javax.swing.table.TableModel#getRowCount()
	 */
	@Override
	public int getRowCount() {
		return filteredData.size();
	}

	/**
	 * Given a row index for the raw (unfiltered) model, return the corresponding index in the
	 * view (filtered) model.
	 *
	 * @param modelRow The row index that corresponds to unfiltered data
	 * @return the index of that row in the filtered data
	 * @see #getModelRow(int)
	 */
	@Override
	public int getViewRow(int modelRow) {
		int unfilteredCount = getUnfilteredRowCount();
		if (getRowCount() == unfilteredCount) {
			return modelRow; // same list; no need to translate values
		}

		if (modelRow >= unfilteredCount) {
			return -1; // out-of-bounds request
		}

		ROW_OBJECT modelValue = allData.get(modelRow);
		return filteredData.indexOf(modelValue);
	}

	/**
	 * Given a row index for the view (filtered) model, return the corresponding index in the
	 * raw (unfiltered) model.
	 *
	 * @param viewRow The row index that corresponds to filtered data
	 * @return the index of that row in the unfiltered data
	 * @see #getViewRow(int)
	 */
	@Override
	public int getModelRow(int viewRow) {
		if (getRowCount() == getUnfilteredRowCount()) {
			return viewRow; // same list; no need to translate values
		}

		if (viewRow >= filteredData.size()) {
			return -1; // out-of-bounds request
		}

		ROW_OBJECT viewValue = filteredData.get(viewRow);
		return allData.indexOf(viewValue);
	}

	@Override
	public int getViewIndex(ROW_OBJECT t) {
		// note: this is faster than it sounds
		int index = filteredData.indexOf(t);
		return index;
	}

	@Override
	public int getModelIndex(ROW_OBJECT t) {
		// note: this is faster than it sounds
		int index = allData.indexOf(t);
		return index;
	}

	/**
	 * Returns the name of this model.
	 * @return the name of this model
	 */
	@Override
	public String getName() {
		return modelName;
	}

	/**
	 * Returns the corresponding row objects for the specified rows.
	 * @param rows the table rows
	 * @return the corresponding database keys
	 */
	public List<ROW_OBJECT> getRowObjects(int[] rows) {
		List<ROW_OBJECT> list = new ArrayList<>(rows.length);
		for (int row : rows) {
			list.add(filteredData.get(row));
		}
		return list;
	}

	/**
	 * Sets the update delay, which is how long the model should wait before updating, after
	 * a change has been made the data
	 * 
	 * @param updateDelayMillis the new update delay
	 * @param maxUpdateDelayMillis the new max update delay; updates will not wait past this time
	 */
	void setUpdateDelay(int updateDelayMillis, int maxUpdateDelayMillis) {
		this.minUpdateDelayMillis = updateDelayMillis;
		this.maxUpdateDelayMillis = maxUpdateDelayMillis;
		updateManager.setUpdateDelay(updateDelayMillis, maxUpdateDelayMillis);
	}

	// see setUpdateDelay
	long getMinDelay() {
		return minUpdateDelayMillis;
	}

	long getMaxDelay() {
		return maxUpdateDelayMillis;
	}

	ThreadedTableModelUpdateMgr<ROW_OBJECT> getUpdateManager() {
		return updateManager;
	}

	void setDefaultTaskMonitor(TaskMonitor monitor) {
		updateManager.setTaskMonitor(monitor);
	}

	/**
	 * Returns the strategy to use for performing adds and removes to this table.   Subclasses can
	 * override this method to customize this process for their particular type of data.   See
	 * the implementations of {@link TableAddRemoveStrategy} for details.
	 * 
	 * <P>Note: The default add/remove strategy assumes that objects to be removed will be the 
	 * same instance that is in the list of this model.   This allows the {@link #equals(Object)} 
	 * and {@link #hashCode()} to be used when removing the object from the list.   If you model 
	 * does not pass the same instance into {@link #removeObject(Object)}, then you will need to 
	 * update your add/remove strategy accordingly.
	 * 
	 * @return the strategy
	 */
	protected TableAddRemoveStrategy<ROW_OBJECT> getAddRemoveStrategy() {
		return binarySearchAddRemoveStrategy;
	}

	public void setIncrementalTaskMonitor(TaskMonitor monitor) {
		SystemUtilities.assertTrue(loadIncrementally, "Cannot set an incremental task monitor " +
			"on a table that was not constructed to load incrementally");
		this.incrementalMonitor = monitor;
		if (worker != null) {
			worker.setTaskMonitor(monitor);
		}
	}

	/**
	 * Adds a listener that will be notified of the first table load of this model.  After the
	 * initial load, the listener is removed.
	 *
	 * @param listener the listener
	 */
	public void addInitialLoadListener(ThreadedTableModelListener listener) {
		listeners.add(new OneTimeListenerWrapper(listener));
	}

	/**
	 * This is a way to know about updates from the table.
	 *
	 * @param listener the listener to add
	 * @see #addInitialLoadListener(ThreadedTableModelListener)
	 * @see #removeThreadedTableModelListener(ThreadedTableModelListener)
	 */
	public void addThreadedTableModelListener(ThreadedTableModelListener listener) {
		listeners.add(listener);
	}

	public void removeThreadedTableModelListener(ThreadedTableModelListener listener) {
		listeners.remove(listener);
	}

	private void notifyFinished(boolean wasCancelled) {
		//
		//				 Unusual Code Alert!
		// It is odd that a 'notify' method is changing the state of a variable.  This is a wart
		// that we've chosen to live with.  We have a variable that we want to stay around as
		// long as the threaded update manager has work to do.  We know that this method is
		// called when no pending work remains.  We use this signal to know that this crufty
		// state variable can now be cleansed.
		//
		// This variable may have already been cleared, but just in case of a cancel situation,
		// we don't want this hanging around and affecting future sorts.
		//
		pendingSortContext = null;

		for (ThreadedTableModelListener listener : listeners) {
			listener.loadingFinished(wasCancelled);
		}
	}

	private void notifyStarted() {
		for (ThreadedTableModelListener listener : listeners) {
			listener.loadingStarted();
		}
	}

	private void notifyPending() {
		for (ThreadedTableModelListener listener : listeners) {
			listener.loadPending();
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * Standard (non-incremental) listener mechanism to receive notifications from the
	 * update manager.
	 */
	private class NonIncrementalUpdateManagerListener implements ThreadedTableModelListener {
		@Override
		public void loadPending() {
			notifyPending();
		}

		@Override
		public void loadingStarted() {
			notifyStarted();
		}

		@Override
		public void loadingFinished(boolean wasCancelled) {
			notifyFinished(wasCancelled);
		}
	}

	/**
	 * Listener to get updates from the {@link ThreadedTableModelUpdateMgr}.  This listener
	 * is only here to make sure that non-loading actions, like sorting, will trigger
	 * notifications to clients.  "Loading" events are handled by the listener passed to the
	 * {@link IncrementalLoadJob} (this {@link IncrementalLoadJobListener}).
	 * <p>
	 * We need the two different listeners due to how they are wired to the update manager.
	 * The {@link IncrementalLoadJobListener} listener is added and removed for each load
	 * request.  We need that listener so that during an incremental load, when multiple starts
	 * and stops come from the update manager, we don't keep adding and removing the progress
	 * bar.  This works great for a normal loading processes.  However, we still need a listener
	 * for when the users manipulates the data, like for filtering or sorting.  Without having
	 * this listener, there is no way to get those notifications.  Thus, this listener has
	 * to be careful not to "get in the way" of the loading listener--the loading listener will
	 * thus always take precedence.
	 */
	private class IncrementalUpdateManagerListener implements ThreadedTableModelListener {
		@Override
		public void loadPending() {
			// don't care about a pending notification--another listener handles that.
		}

		@Override
		public void loadingStarted() {
			if (isWorkerBusy()) {
				// the job will always handle notifications when it is running
				return;
			}
			notifyStarted();
		}

		@Override
		public void loadingFinished(boolean wasCancelled) {
			if (isWorkerBusy()) {
				// the job will always handle notifications when it is running
				return;
			}
			notifyFinished(wasCancelled);
		}
	}

	/**
	 * A special internal listener for the model to know when incremental jobs begin and end.
	 * This allows the model to ignore repeated start/finished events from the update manager
	 * when it is in 'load incrementally' mode.
	 */
	protected class IncrementalLoadJobListener extends IncrementalJobListener {
		@Override
		void loadingStarted() {
			notifyStarted();
		}

		@Override
		void loadingFinished(boolean wasCancelled) {
			notifyFinished(wasCancelled);
		}
	}

	/**
	 * A listener wrapper that will pass on notifications and then remove itself after
	 * the loadFinished() call so that not more events are broadcast.
	 */
	private class OneTimeListenerWrapper implements ThreadedTableModelListener {
		private final ThreadedTableModelListener delegate;

		OneTimeListenerWrapper(ThreadedTableModelListener wrapper) {
			this.delegate = wrapper;
		}

		@Override
		public void loadPending() {
			delegate.loadPending();
		}

		@Override
		public void loadingStarted() {
			delegate.loadingStarted();
		}

		@Override
		public void loadingFinished(boolean wasCancelled) {
			removeThreadedTableModelListener(this);
			delegate.loadingFinished(wasCancelled);
		}
	}
}
