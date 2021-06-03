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

import static docking.widgets.table.threaded.TableUpdateJob.JobState.*;

import java.util.*;

import javax.swing.SwingUtilities;

import docking.widgets.table.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.Algorithms;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * State machine object for performing the various update functions on a ThreadedTableModel.
 * The general pattern is to:
 * <ol>
 * 	<li>Load </li>
 *  <li>Filter </li>
 *  <li>Process individual adds and removes </li>
 *  <li>Sort </li>
 *  <li>Set the processed data back on the model</li>
 * </ol>
 * <p>
 * Not all the update functions are performed on a run of a TableUpdateJob.  If the reloadData flag is
 * not set, the the data is just copied from the model's current list, instead of calling the model's
 * loadData() method. If the sortComparator is null,
 * then the data is not sorted (for example, when only filtering needs to be done).  If there
 * are no add/removes in the list, then that step does nothing.
 * <p>
 * Before the job completes, new calls to sort and filter can be called.  If the job is past the
 * stage of the new call, the <code>monitor</code> is cancelled, causing the current stage to abort.  
 * The next state of this job is set to the appropriate state for the call, the monitor is 
 * reset, and the job begins executing the next stage, based upon the new call.
 *
 * @param <T> the type of data that each row in the table represents.
 */
public class TableUpdateJob<T> {

	//@formatter:off
	static enum JobState {
		NOT_RUNNING, 
		LOADING, 
		FILTERING, 
		ADD_REMOVING, 
		SORTING, 
		APPLYING, 
		DONE
	}
	//@formatter:on

	private ThreadedTableModel<T, ?> model;
	private TaskMonitor monitor;

	private TableData<T> sourceData;
	private TableData<T> updatedData;
	private boolean disableSubFiltering = SystemUtilities.getBooleanProperty(
		RowObjectFilterModel.SUB_FILTERING_DISABLED_PROPERTY, false);

	private volatile boolean reloadData;
	private volatile boolean doForceSort;
	private volatile boolean doForceFilter = true; // always refilter, unless told not to (like when sorting)
	private volatile TableSortingContext<T> newSortContext; // sort info to use for the next sort
	private TableSortingContext<T> lastSortContext; // sort info that was used for the last complete sort
	protected List<AddRemoveListItem<T>> addRemoveList = new ArrayList<>();

	private volatile JobState currentState;
	private volatile JobState pendingRequestedState;

	// Note: we leave this debug code here because debugging job flow is so difficult, that it
	// is nice to not have to re-invent this when it is needed.
	private List<JobState> debugStateHistory = new ArrayList<>();

	/** a flag to signal that this job is no longer being used and can die a horrible death */
	private volatile boolean isFired;

	TableUpdateJob(ThreadedTableModel<T, ?> model, TaskMonitor taskMonitor) {
		this.model = model;
		this.monitor = taskMonitor;
		setState(NOT_RUNNING);
	}

	/**
	 * Meant to be called by subclasses, not clients.  This method will trigger this job not 
	 * to load data, but rather to use the given data.
	 * 
	 * @param data The data to process.
	 */
	protected void setData(TableData<T> data) {
		this.sourceData = data;
	}

	/**
	 * Allows the precise disabling of the filter operation.  For example, when the user sorts, 
	 * no filtering is needed.  If the filter has changed, then a filter will take place, 
	 * regardless of the state of this variable.
	 * 
	 * @param force false to reuse the current filter, if possible.
	 */
	protected void setForceFilter(boolean force) {
		this.doForceFilter = force;
	}

	/**
	 * The basic run() method that executes the state machine.
	 */
	public void run() {
		gotoNextState(); // initialize the currentState.

		while (currentState != DONE) {
			try {
				processState(currentState);
			}
			catch (CancelledException ex) {
				// handled in gotoNextState
			}
			catch (Exception e) {
				if (!isFired) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
					break;
				}
			}

			gotoNextState();
		}
	}

	/**
	 * Forces this job to completely reload the data, instead of copying from
	 * the model's current data.  This call is not allowed on the currently running job and is only
	 * appropriate for a pending job.
	 */
	public synchronized void reload() {
		if (currentState != NOT_RUNNING) {
			throw new IllegalStateException("Cannot reload once a job starts");
		}

		isFired = false; // reset the cancel flag, since we are reloading
		reloadData = true;
		addRemoveList.clear();
		if (newSortContext == null) {
			newSortContext = model.getSortingContext();
		}
	}

	/**
	 * Adds the Add/Remove item to the list of items to be processed in the add/remove phase. This
	 * call is not allowed on running jobs, only pending jobs.
	 *   
	 * @param item the add/remove item to add to the list of items to be processed in the add/remove
	 *            phase of this job.
	 * @param maxAddRemoveCount the maximum number of add/remove jobs to queue before performing 
	 *        a full reload
	 */
	public synchronized void addRemove(AddRemoveListItem<T> item, int maxAddRemoveCount) {
		if (currentState != NOT_RUNNING) {
			throw new IllegalStateException("Cannot add or remove once a job starts");
		}

		if (reloadData) {
			return; // no need to process addRemove, since a total reload is scheduled.
		}

		if (addRemoveList.size() > maxAddRemoveCount) {
			reload();
			return;
		}
		addRemoveList.add(item);
	}

	/**
	 * Sets the TableColumnComparator to use for sorting the data.  This method can be called on
	 * the currently running job as well as the pending job.  If called on the running job, the effect
	 * depends on the running job's state:
	 * <ul>
	 *     <li>If the sort state hasn't happened yet, all it does is set the comparator for when 
	 *     the sort occurs.  
	 *     <li>If the sort state has already been started or completed, then this method attempts
	 *      to stop the current process phase and cause the state
	 * 		machine to return to the sort phase.
	 *     <li>If the current job has already entered the DONE state, then the sort cannot 
	 *     take effect in this job and a false value is returned to indicate the
	 * sort was not handled by this job.
	 * </ul>  
	 * @param newSortingContext the TableColumnComparator to use to sort the data.
	 * @param forceSort True signals to re-sort, even if this is already sorted
	 * @return true if the sort can be processed by this job, false if this job is essentially already
	 * completed and therefor cannot perform the sort job.
	 */
	public synchronized boolean requestSort(TableSortingContext<T> newSortingContext,
			boolean forceSort) {
		if (currentState == DONE) {
			return false;
		}
		this.doForceSort = forceSort;
		this.newSortContext = newSortingContext;
		if (hasSorted()) {
			// the user has requested a new sort, and we've already sorted, so we need to sort again
			monitor.cancel();
			pendingRequestedState = SORTING;
		}
		return true;
	}

	/**
	 * Tells the job that the filter criteria has changed.  This method can be called on
	 * the currently running job as well as the pending job.  If called on the running job, the 
	 * effect depends on the running job's state:
	 * <ul>
	 * 	  <li>If the filter state hasn't happened yet, then nothing needs to be done as this job 
	 * 			will filter later anyway. 
	 *    <li>If the filter state has already been started or completed, then this method 
	 *    		attempts to stop the current process phase and cause the state machine to 
	 *    		return to the filter phase. 
	 *    <li>If the current job has already entered the DONE state, then the filter cannot take
	 *     		effect in this job and a false value is returned to indicate the filter was 
	 *     		not handled by this job.
	 * </ul> 
	 * @return true if the filter can be processed by this job, false if this job is essentially already
	 * completed and therefor cannot perform the filter job.
	 */
	public synchronized boolean requestFilter() {
		if (currentState == DONE) {
			return false;
		}
		if (hasFiltered()) {
			// the user has requested a new filter; we've already filtered, so filter again
			monitor.cancel();
			pendingRequestedState = FILTERING;
		}
		return true;
	}

	/**
	 * Returns true if this job has already started or completed the sort phase.
	 * @return true if this job has already started or completed the sort phase.
	 */
	private boolean hasSorted() {
		return (currentState.compareTo(SORTING) >= 0);
	}

	/**
	 * Returns true if this job has already started or completed the filter phase.
	 * @return true if this job has already started or completed the filter phase.
	 */
	private boolean hasFiltered() {
		return (currentState.compareTo(FILTERING) >= 0);
	}

	/**
	 * Transitions to the next state of this state machine. Handles the special case if the
	 * monitor has been cancelled by a call to sort() or filter().  In either of these cases,
	 * the recover state would have been set and indicates that the monitor should be reset and
	 * the state machine should transition to the recover state instead of the next scheduled
	 * state. If the monitor has been cancelled, and no recover state has been set, then the
	 * job was cancelled by the user and the job will end.
	 */
	private synchronized void gotoNextState() {
		if (monitor.isCancelled()) {
			if (pendingRequestedState != null) {
				setState(pendingRequestedState);
				pendingRequestedState = null;
				monitor.clearCanceled();
			}
			else {
				setState(DONE);
			}
		}
		else {
			setState(getNextState(currentState));
		}
	}

	/**
	 * YOU SHOULD BE SYNCHRNOIZED WHEN CALLING THIS!
	 */
	private void setState(JobState state) {
		debugStateHistory.add(state);
		currentState = state;
	}

	/**
	 * Returns the next state to transition to after the given state.
	 * @param state the current state to transition from.
	 * @return the next state to be processed after the given state.
	 */
	private JobState getNextState(JobState state) {
		switch (state) {
			case NOT_RUNNING:
				return LOADING;
			case LOADING:
				return FILTERING;
			case FILTERING:
				return ADD_REMOVING;
			case ADD_REMOVING:
				return SORTING;
			case SORTING:
				return APPLYING;
			case APPLYING:
			default:
				return DONE;
		}
	}

	/**
	 * Calls the appropriate method to process the given state.
	 * @param state the state to process.
	 * @throws CancelledException if the job was cancelled
	 */
	private void processState(JobState state) throws CancelledException {
		switch (state) {
			case LOADING:
				loadData();
				break;
			case FILTERING:
				doFilterData();
				break;
			case ADD_REMOVING:
				doProcessAddRemoves();
				break;
			case SORTING:
				sortData();
				break;
			case APPLYING:
				applyData();
				break;
			default:
		}
	}

	/**
	 * Work method to load data for the follow on states.  If the reloadData flag is set, the data
	 * will be totally reloaded, else the data will be copied from the model's current data.
	 */
	private void loadData() throws CancelledException {
		monitor.setMessage("Loading " + model.getName() + "...");

		if (reloadData) {
			// load the data from scratch
			List<T> newData = model.load(monitor);
			sourceData = TableData.createFullDataset(newData);
		}
		else if (sourceData == null) {
			// no loading; just updating
			sourceData = pickExistingTableData();
			lastSortContext = sourceData.getSortContext();
		}
		// else - the source data has been given to us explicitly, like during an incremental load

		monitor.setMessage("Done loading");
	}

	/**
	 * Picks the table data to use for all future states (e.g., filtering, sorting, etc).  Data
	 * can be reused if its filter is a superset of the pending filter.  Likewise, if the 
	 * pending filter is itself a superset of the current filter, then this code will walk 
	 * backwards, starting at the current table data, until it finds either the root dataset or
	 * a child of the root whose filter is a superset of the pending filter.
	 * <p>
	 * Reusing table data in this way has the potential to consume too much memory (in the case
	 * where the initial dataset is large and each subsequent filter is a subset of the 
	 * previous filter, where each filter does't significantly reduce the newly filtered dataset.
	 * <p>
	 * Since much memory could be consumed, we provide an option in the tool to disable this
	 * reuse of filtered data.  When not in use, each filter change will perform a full refilter.
	 * This is not an issue for tables with moderate to small-sized datasets.
	 * 
	 * @return the initial data to use for future filter and sort operations.
	 */
	private TableData<T> pickExistingTableData() {

		if (disableSubFiltering) {
			return model.getAllTableData();
		}

		TableData<T> startSourceData = getReusableFilteredData(); // this may be filtered
		if (startSourceData == null) {
			// must use all data due to a new filter
			startSourceData = model.getAllTableData();
		}
		TableData<T> copy = startSourceData.copy();
		return copy;
	}

	/** 
	 * Gets any existing data that matches the current filter, if any.
	 * @return data that should be the start point for the next filter state; null if there 
	 *          is no filter set or if the current data's filter does not match the pending filter
	 */
	private TableData<T> getReusableFilteredData() {
		TableData<T> allTableData = model.getAllTableData();
		TableData<T> currentAppliedData = model.getCurrentTableData();
		if (allTableData == currentAppliedData) { // yes, '=='
			return null; // same data; no filter
		}

		if (currentAppliedData.isUnrelatedTo(allTableData)) {
			// the data has changed such that the currently applied data is not progeny of
			// the current master dataset
			return null;
		}

		TableFilter<T> appliedOrPendingFilter = model.getTableFilter();
		TableData<T> alreadyFilteredData =
			currentAppliedData.getLowestLevelSourceDataForFilter(appliedOrPendingFilter);
		return alreadyFilteredData;
	}

	/**
	 * Returns true if the data needs to be sorted.
	 * @return true if the data needs to be sorted.
	 */
	private boolean needsSorting() {
		if (doForceSort) {
			return true;
		}

		if (hasNewSort()) {
			return true;
		}

		if (tableSortDiffersFromSourceData()) {
			// The source of the data we are manipulating is sorted in a way that may be 
			// different from the sort state of the table.  In that case, we have to sort the 
			// data we are creating to match the table and not the source data--the table is
			// always the truth keeper of the correct sort.
			newSortContext = model.getSortingContext();
			return true;
		}

		return false;
	}

	private boolean hasNewSort() {
		if (newSortContext == null) {
			return false;
		}

		// the new sort differs from the last one
		return !newSortContext.equals(lastSortContext);
	}

	/** True if the sort applied to the table is not the same as that in the source dataset */
	private boolean tableSortDiffersFromSourceData() {
		// Note: at this point in time we do not check to see if the table is user-unsorted.  It
		//       doesn't seem to hurt to leave the original source data sorted, even if the 
		//       current context is 'unsorted'.  In that case, this method will return true, 
		//       that the sorts are different.  But, later in this job, we check the new sort and
		//       do not perform sorting when 'unsorted'
		return !SystemUtilities.isEqual(sourceData.getSortContext(), model.getSortingContext());
	}

	/**
	 * Returns true if the sort can take a shortcut and just reverse the order of the data.
	 * @return true if the sort can take a shortcut and just reverse the order of the data.
	 */
	private boolean isCurrentSortReversable() {
		if (lastSortContext == null || doForceSort) {
			return false;
		}
		// we know that the direction of the sort is different because of a previous call to equals()
		return lastSortContext.isReverseOf(newSortContext);
	}

	/**
	 * Work method to sort the data.
	 */
	private void sortData() {
		if (!needsSorting()) {
			return;
		}

		List<T> sortData = updatedData.getData();
		if (isCurrentSortReversable()) {
			Collections.reverse(sortData);
		}
		else {
			initializeSortCache();

			maybeSortSourceData();
			doSortData(sortData);

			clearSortCache();
		}

		lastSortContext = monitor.isCancelled() ? null : newSortContext;
		updatedData.setSortContext(lastSortContext);
	}

	private void doSortData(List<T> data) {

		if (newSortContext.isUnsorted()) {
			return;
		}

		int size = data.size();
		monitor.setMessage("Sorting " + model.getName() + " (" + size + " rows)" + "...");
		monitor.initialize(size);

		Comparator<T> comparator = newSortContext.getComparator();
		Algorithms.mergeSort(data, comparator, monitor);

		monitor.setMessage("Done sorting");
	}

	private void maybeSortSourceData() {
		//
		// Usually the source data is sorted before any filter is applied.  However, this is not
		// the case when a load of new data is followed directly by a filter action.  We rely on 
		// the source data being sorted in order to perform fast translations from the table's 
		// view to the table's model when it is filtered.  Thus, make sure that any time we are 
		// sorting the filtered data, that the source data too is sorted.
		//
		if (sourceData == updatedData) {
			// they are the same dataset; it will be sorted after this call
			return;
		}

		if (sourceData.isSorted()) {
			// this is the typical case
			return;
		}

		doSortData(sourceData.getData());

		if (monitor.isCancelled()) {
			sourceData.setSortContext(null);
		}
		else {
			sourceData.setSortContext(newSortContext);
		}
	}

	/**
	 * Work method to process the add/remove items.
	 */
	private void doProcessAddRemoves() throws CancelledException {

		initializeSortCache();
		try {
			TableAddRemoveStrategy<T> strategy = model.getAddRemoveStrategy();
			strategy.process(addRemoveList, updatedData, monitor);
		}
		finally {
			clearSortCache();
		}
	}

	/** When sorting we cache column value lookups to increase speed. */
	private void initializeSortCache() {
		model.initializeCache();
	}

	/** Clear the column value lookup cache, to give back memory */
	private void clearSortCache() {
		model.clearCache();
	}

	/**
	 * Work method to filter the data.
	 */
	private void doFilterData() throws CancelledException {

		if (canReuseCurrentFilteredData()) {
			// the source data hasn't changed since the last filter, no need to refilter
			copyCurrentFilterData();
			return;
		}

		TableData<T> filterSourceData = sourceData;
		int size = filterSourceData.size();
		monitor.setMessage("Filtering " + model.getName() + " (" + size + " rows)...");

		List<T> list = filterSourceData.getData();
		List<T> result = model.doFilter(list, lastSortContext, monitor);
		if (result == list) { // yes, '=='
			// no filtering took place
			updatedData = filterSourceData;
		}
		else {
			// the derived data is sorted the same as the source data
			TableSortingContext<T> sortContext = filterSourceData.getSortContext();
			updatedData = TableData.createSubDataset(filterSourceData, result, sortContext);
			updatedData.setTableFilter(model.getTableFilter());
		}

		monitor.setMessage(
			"Done filtering " + model.getName() + " (" + updatedData.size() + " rows)");
	}

	private void copyCurrentFilterData() {
		TableData<T> currentFilteredData = getCurrentFilteredData();
		updatedData = currentFilteredData.copy(sourceData); // copy; don't modify the UI's version

		// We are re-using the filtered data, so use too its sort
		lastSortContext = updatedData.getSortContext();
	}

	/** 
	 * The current data can be re-used when the data and filter have not changed 
	 * (this implies a sort only operation)
	 */
	private boolean canReuseCurrentFilteredData() {
		//
		// We can skip filtering if:
		// -we have not been told to filter
		// -the table is not currently filtered, or is filtered, but
		// --the source data that the filtered data is based upon hasn't changed
		// --the filter hasn't changed		
		//		
		if (doForceFilter) {
			return false;
		}

		TableData<T> currentTableData = getCurrentFilteredData();
		TableFilter<T> appliedOrPendingFilter = model.getTableFilter();

		if (currentTableData.isUnrelatedTo(sourceData)) {
			// the current table's data is going to be changed by this Job
			return false;
		}

		return currentTableData.matchesFilter(appliedOrPendingFilter);
	}

	private TableData<T> getCurrentFilteredData() {
		TableData<T> currentData = model.getCurrentTableData();
		return currentData;
	}

	/**
	 * Work method to set the data back into the ThreadTableModel.
	 */
	private void applyData() {

		TableData<T> allData = sourceData.getRootData();
		try {
			SwingUtilities.invokeAndWait(() -> {
				if (isFired) {
					return; // in case we were cancelled whilst being posted
				}
				model.setModelState(allData, updatedData);
			});
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
	}

	public synchronized void cancel() {
		isFired = true; // let the job die, ignoring any issues that may arise
		pendingRequestedState = DONE;
		monitor.cancel();
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + " - [state history=\n" + getStateHistoryString() + "]";
	}

	private String getStateHistoryString() {
		StringBuilder buffy = new StringBuilder();
		for (JobState state : debugStateHistory) {
			buffy.append('\t').append(state).append('\n');
		}
		return buffy.toString();
	}
}
