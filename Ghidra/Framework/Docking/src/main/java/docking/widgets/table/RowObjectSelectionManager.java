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
package docking.widgets.table;

import java.awt.Rectangle;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.swing.*;
import javax.swing.event.*;

import org.apache.commons.collections4.map.LazyMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import ghidra.util.Msg;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import utilities.util.ArrayUtilities;
import utilities.util.reflection.ReflectionUtilities;

/**
 * A class to track and restore selections made in a table.  We use this in the docking
 * environment primarily due to the heavy usage of filtering for most tables.  As tables are
 * filtered, the contents change (and then change back when the filter is removed).  It is nice
 * to be able to filter a table, select an item of interest, and then unfilter the table to see
 * that item in more context.
 * 
 * @param <T> the row type 
 */
public class RowObjectSelectionManager<T> extends DefaultListSelectionModel
		implements SelectionManager {

	/**
	 * How big is too big?  Some things to consider:
	 * <pre>
	 * 1) There are many tables in the tool that could be active at once
	 * 2) Many tables will reload during analysis or undo/redo
	 * 3) Each reload will trigger a 'selection restore' *when there is a selection in the table*
	 * 4) Each selection restore will trigger a map to be created, where each key is a row object
	 * 5) Each map is built in the Swing thread
	 * 6) There may be many maps being built for a major domain object change
	 * 7) The potential memory consumption is (number of maps * size of each table)
	 * </pre>
	 * Each map will be immediately available for garbage collection.  But, there still seems
	 * to be some reasonable upper-bound that we can put in place to not fall into a degenerate
	 * case that consumes too much memory.  (Not to mention the work of building and collecting
	 * the maps).
	 * <P>
	 * This value can always be changed if it seems to restrictive (user selections do not
	 * persist) or too much work is being done (we haven't yet noticed this, but it could be
	 * happening to end-users).
	 */
	private static final int ARTIFICIAL_ROW_COUNT_THRESHOLD = 10000;

	private Logger log = LogManager.getLogger(RowObjectSelectionManager.class);
	private DateFormat DATE_FORMAT = new SimpleDateFormat("hh:mm:ss:SSSS");

	private WeakSet<SelectionManagerListener> listeners =
		WeakDataStructureFactory.createSingleThreadAccessWeakSet();

	private JTable table;
	private FilterModelAdapter modelAdapter;

	/**
	 * A flag used to track when updates or requests to update the selection are made.  This is
	 * used to throw away requests to repair selections that have been superseded by new requests.
	 */
	private long lastSelectionUpdateTimeStamp;

	private boolean ignoreSelectionChange;
	private boolean restoringSelection;

	public RowObjectSelectionManager(JTable table, RowObjectTableModel<T> model) {
		this.table = table;

		if (model instanceof RowObjectFilterModel<?>) {
			modelAdapter = new FilterModelPassThrough((RowObjectFilterModel<T>) model);
		}
		else {
			modelAdapter = new FilterModelAdapter(model);
		}

		modelAdapter.addTableModelListener(this);
		installListSelectionListener();
	}

	@Override
	public void addSelectionManagerListener(SelectionManagerListener listener) {
		listeners.add(listener);
	}

	@Override
	public void removeSelectionManagerListener(SelectionManagerListener listener) {
		listeners.remove(listener);
	}

	private void installListSelectionListener() {
		ListSelectionModel oldSelectionModel = table.getSelectionModel();
		if (!(oldSelectionModel instanceof DefaultListSelectionModel)) {
			Msg.debug(this,
				"Don't know how to extract listeners from a " +
					"ListSelectionModel that is not a DefaultListSelectionModel.  " +
					"Any listeners installed on this model before installing this " +
					"TableFilterPanel will be lost!");
		}
		else {
			DefaultListSelectionModel defaultListSelectionModel =
				(DefaultListSelectionModel) oldSelectionModel;
			ListSelectionListener[] installedListeners =
				defaultListSelectionModel.getListSelectionListeners();

			for (ListSelectionListener listener : installedListeners) {
				addListSelectionListener(listener);
			}
		}

		// so it isn't added more than once, as it adds it again when we set it on the table
		removeListSelectionListener(table);
		table.setSelectionModel(this);
	}

	@Override
	public void dispose() {
		trace("dispose()");
		modelAdapter.removeTableModelListener(this);
		modelAdapter.clearLastSelectedObjects();
	}

	@Override
	public void clearSavedSelection() {
		trace("clearing saved selection");
		modelAdapter.clearLastSelectedObjects();
		lastSelectionUpdateTimeStamp = -1;
	}

	@Override
	public void clearSelection() {
		ignoreSelectionChange = true;
		super.clearSelection();
	}

	@Override
	protected void fireValueChanged(int firstIndex, int lastIndex, boolean isAdjusting) {
		if (!shouldTrackSelection(isAdjusting, firstIndex)) {
			superFireValueChanged(firstIndex, lastIndex, isAdjusting, false);
			return;
		}

		// when editing, the selection changes are valid, but we get notified of them
		// as 'adjusting', so we need to handle that special case
		boolean isTransientChange = (isAdjusting && !table.isEditing());
		if (isTransientChange) {
			superFireValueChanged(firstIndex, lastIndex, isAdjusting, false);
			return;
		}

		int[] selectedRows = table.getSelectedRows();
		saveSelectionState(selectedRows);

		superFireValueChanged(firstIndex, lastIndex, isAdjusting, true);
	}

	private void superFireValueChanged(int firstIndex, int lastIndex, boolean isAdjusting,
			boolean isTrackingSelectionChange) {

		trace("superFireValueChanged(" + firstIndex + "," + lastIndex + ") ");

		if (!isAdjusting && isTrackingSelectionChange) {
			// New selection changes will invalidate all
			// pending (posted to the Swing thread) calls to repair selection
			trace("\tresetting last selection timestamp");
			lastSelectionUpdateTimeStamp = -1;
		}
		super.fireValueChanged(firstIndex, lastIndex, isAdjusting);
	}

	/** checks to see if we are ignoring selection changes AND will reset the ignore state */
	private boolean shouldTrackSelection(boolean isAdjusting, int firstIndex) {
		if (restoringSelection) {
			return false;
		}

		if (!ignoreSelectionChange) {
			return true;
		}

		// The assumption here is that we were ignoring changes while the model was in the
		// adjusting state.  When the state is turned off, then we want to stop ignoring
		// changes
		if (!isAdjusting) {
			ignoreSelectionChange = false;
			if (table.getSelectedRow() != -1) {
				return true; // the adjustments are done and there is a valid selection
			}
		}
		return false;
	}

	private void saveSelectionState(int[] selectedRows) {
		traceRows("saveSelectionState(): ", selectedRows);
		trace("\tfrom", new Throwable());

		modelAdapter.clearLastSelectedObjects();

		if (modelAdapter.getUnfilteredRowCount() == 0) {
			// we can sometimes be called from a programmatic selection being made when there is
			// not data in the table
			return;
		}

		trace("\tstoring data");
		List<T> lastSelectedObjects = translateRowsToValues(selectedRows);
		modelAdapter.setLastSelectedObjects(lastSelectedObjects);
		trace("\tfinal stored data: " + toString(lastSelectedObjects));
	}

	private String toString(List<T> list) {
		if (list.isEmpty()) {
			return "<empty>";
		}

		return list.size() + " items - " + list.get(0);
	}

	// Note: this method only works for the active table contents (we cannot guarantee that old
	//       view values (like before a filter) will be correctly mapped).
	protected List<T> translateRowsToValues(int[] viewRows) {
		List<T> values = new ArrayList<>();

		for (int viewRow : viewRows) {
			T rowObject = modelAdapter.getRowObject(viewRow);
			values.add(rowObject);
		}
		return values;
	}

	private String rowsToString(int[] rows) {
		if (rows.length == 0) {
			return "<empty>";
		}

		StringBuilder buffy = new StringBuilder("[");
		int length = Math.min(rows.length, 100);
		for (int i = 0; i < length; i++) {
			int row = rows[i];
			buffy.append(row).append(',');
		}

		if (rows.length > 0) {
			buffy.deleteCharAt(buffy.length() - 1); // strip off last comma
		}

		if (length != rows.length) {
			// we capped the number of rows to display
			buffy.append("...");
		}

		buffy.append(']');
		return buffy.toString();
	}

	@Override
	public void tableChanged(TableModelEvent e) {
		// we may have saved selections to restore after table updates
		maybeRepairSelection();
	}

	private void maybeRepairSelection() {
		trace("maybeRepairSelection()");
		if (modelAdapter.getLastSelectedObjects().isEmpty()) {
			trace("\tselection is empty");
			return;
		}

		int rowCount = modelAdapter.getRowCount();
		if (rowCount == 0) {
			trace("\tno rows in the table to select");
			return;
		}

		repairSelection();
	}

	private void repairSelection() {
		lastSelectionUpdateTimeStamp = System.currentTimeMillis();

		if (selectionHistoryExpired(lastSelectionUpdateTimeStamp)) {
			return;
		}

		// the reselect sometimes needs to be done after the table has rebuilt itself
		// after this call has been made
		final long currentRequestTimeStamp = lastSelectionUpdateTimeStamp;
		SwingUtilities.invokeLater(() -> {
			// re-check the assumptions above to see if anyone has changed the selection
			// while we were queued-up
			trace("\trepair selection swing later - " +
				getTimestampString(lastSelectionUpdateTimeStamp));
			if (selectionHistoryExpired(currentRequestTimeStamp)) {
				return;
			}

			int[] updatedViewRows = translateSavedObjectSelectionToRowIndexes();
			selectRows(updatedViewRows);
		});
	}

	private int[] translateSavedObjectSelectionToRowIndexes() {
		List<T> lastSelectedObjects = modelAdapter.getLastSelectedObjects();
		if (lastSelectedObjects.isEmpty()) {
			// no saved selection
			return new int[0];
		}

		trace("\ttranslate this objects back to indices: " + lastSelectedObjects.get(0));
		Map<Object, List<Integer>> objectRowMap = mapAllTableRowObjectToIndexes();
		if (objectRowMap.isEmpty()) {
			// empty table or too many rows
			return new int[0];
		}

		List<Integer> rowsList = translateRowObjectsToIndices(lastSelectedObjects, objectRowMap);
		int[] asInts = rowsList.stream().mapToInt(i -> i).toArray();
		return asInts;
	}

	private List<Integer> translateRowObjectsToIndices(List<T> rowObjects,
			Map<Object, List<Integer>> objectRowMap) {
		List<Integer> rowsList = new ArrayList<>();
		int rowCount = modelAdapter.getRowCount();
		for (int i = 0; i < rowObjects.size(); i++) {
			Object object = rowObjects.get(i);
			List<Integer> integerList = objectRowMap.get(object);
			if (integerList == null) {
				continue;
			}

			Iterator<Integer> iterator = integerList.iterator();
			for (; iterator.hasNext();) {
				Integer rowIndex = iterator.next();
				iterator.remove(); // remove this value so that we don't process it later
				if (rowIndex < rowCount) {
					rowsList.add(rowIndex);
					break;
				}
			}
		}
		return rowsList;
	}

	private Map<Object, List<Integer>> mapAllTableRowObjectToIndexes() {
		// gather the indexes...
		// Note: we use a list of row values for each object because the table may contain
		// duplicate entries, which we have to keep at separate indices in order to restore selection
		int rowCount = modelAdapter.getRowCount();
		if (rowCount > ARTIFICIAL_ROW_COUNT_THRESHOLD) {
			return Collections.emptyMap();
		}

		Map<Object, List<Integer>> objectRowMap =
			LazyMap.lazyMap(new HashMap<>(), () -> new ArrayList<>());
		for (int i = 0; i < rowCount; i++) {
			Object object = modelAdapter.getRowObject(i);
			List<Integer> integerList = objectRowMap.get(object);
			integerList.add(i);
			objectRowMap.put(object, integerList);
		}

		return objectRowMap;
	}

	private String getTimestampString(long timestamp) {
		return DATE_FORMAT.format(new Date(timestamp));
	}

	private void selectRows(int[] selectedViewRows) {
		if (selectedViewRows.length == 0) {
			return; // either no previous selection, or selection has been filtered out
		}

		if (restoreSelectedRows(selectedViewRows)) {

			// scroll to the beginning of the selection
			Rectangle cellRect = table.getCellRect(selectedViewRows[0], 0, true);
			if (cellRect != null) {
				table.scrollRectToVisible(cellRect);
			}
		}
	}

	private boolean restoreSelectedRows(int[] rows) {
		traceRows("restoreSelectedRows(): ", rows);
		if (ArrayUtilities.isArrayPrimativeEqual(rows, table.getSelectedRows())) {
			trace("\tselection hasn't changed--nothing to do");
			// the selection is the same, nothing to change; don't send out excess events
			return false;
		}

		trace("\tpreparing to restore selection");
		notifyRestoringSelection(true);
		restoringSelection = true;

		ListSelectionModel selectionModel = table.getSelectionModel();
		selectionModel.setValueIsAdjusting(true);
		selectionModel.clearSelection();
		for (int row : rows) {
			selectionModel.addSelectionInterval(row, row);
		}
		selectionModel.setValueIsAdjusting(false);

		restoringSelection = false;
		notifyRestoringSelection(false);
		trace("\tdone restoring selection");
		return true;
	}

	private void notifyRestoringSelection(boolean isPreRestore) {
		for (SelectionManagerListener listener : listeners) {
			listener.restoringSelection(isPreRestore);
		}
	}

	private void trace(String s) {

		trace(s, null);
	}

	private void trace(String s, Throwable t) {
		Throwable filtered = t == null ? null : ReflectionUtilities.filterJavaThrowable(t);
		log.trace(s, filtered);
	}

	private void traceRows(String message, int[] rows) {
		if (log.isTraceEnabled()) {
			// we check here to avoid building up the string that represents the rows
			trace(message + rowsToString(rows));
		}
	}

	private boolean selectionHistoryExpired(long currentTimestamp) {
		if (lastSelectionUpdateTimeStamp != currentTimestamp) {
			trace("\tlast selection no longer valid--newer request has been made.\n" +
				"\t\tvalidating time: " + getTimestampString(currentTimestamp) +
				" against most recent: " + getTimestampString(lastSelectionUpdateTimeStamp));
			// another repair request has been posted since we were told to execute
			return true;
		}
		return false;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * Base class for models that are not themselves FilterModel implementations.
	 */
	private class FilterModelAdapter implements RowObjectFilterModel<T> {

		private SelectionStorage<T> selectionStorage;
		protected RowObjectTableModel<T> model;

		@SuppressWarnings("unchecked")
		// SelectionStorage cast - this could technically be an exception.  Might as well except
		// in those case and fix them up when they happen.  We expect that a table model of
		// type RowObjectTableModel<T> to implement the SelectionStorage<T>, with T being the
		// same type (Java doesn't enforce this).
		FilterModelAdapter(RowObjectTableModel<T> model) {
			this.model = model;
			if (model instanceof SelectionStorage) {
				this.selectionStorage = (SelectionStorage<T>) model;
			}
			else {
				this.selectionStorage = new SelectionStorageHelper();
			}
			setLastSelectedObjects(new ArrayList<T>());
		}

		@Override
		public String getName() {
			return model.getName();
		}

		@Override
		public int getModelRow(int viewRow) {
			return viewRow; // these are the same
		}

		@Override
		public int getViewRow(int modelRow) {
			return modelRow; // this are the same
		}

		@Override
		public boolean isFiltered() {
			return false; // this can never be filtered
		}

		@Override
		public void setTableFilter(TableFilter<T> filter) {
			// no-op; can't filter
		}

		@Override
		public TableFilter<T> getTableFilter() {
			return null;
		}

		@Override
		public List<T> getUnfilteredData() {
			return model.getModelData();
		}

		@Override
		public int getUnfilteredRowCount() {
			return model.getRowCount();
		}

		@Override
		public void fireTableDataChanged() {
			model.fireTableDataChanged();
		}

		@Override
		public void addTableModelListener(TableModelListener listener) {
			model.addTableModelListener(listener);
		}

		@Override
		public void removeTableModelListener(TableModelListener listener) {
			model.removeTableModelListener(listener);
		}

		List<T> getLastSelectedObjects() {
			return selectionStorage.getLastSelectedObjects();
		}

		void setLastSelectedObjects(List<T> lastSelectedObjects) {
			selectionStorage.setLastSelectedObjects(lastSelectedObjects);
		}

		void clearLastSelectedObjects() {
			getLastSelectedObjects().clear();
		}

		@Override
		public T getRowObject(int viewRow) {
			return model.getRowObject(viewRow);
		}

		@Override
		public int getRowIndex(T t) {
			// note: this is the 'view' row
			return model.getRowIndex(t);
		}

		@Override
		public int getViewIndex(T t) {
			// this is the same as the model, as we are an adapter
			return model.getRowIndex(t);
		}

		@Override
		public int getModelIndex(T t) {
			return model.getRowIndex(t);
		}

		@Override
		public List<T> getModelData() {
			return model.getModelData();
		}

		@Override
		public int getRowCount() {
			return model.getRowCount();
		}

		@Override
		public int getColumnCount() {
			return model.getColumnCount();
		}

		@Override
		public String getColumnName(int columnIndex) {
			return model.getColumnName(columnIndex);
		}

		@Override
		public Class<?> getColumnClass(int columnIndex) {
			return model.getColumnClass(columnIndex);
		}

		@Override
		public boolean isCellEditable(int rowIndex, int columnIndex) {
			return model.isCellEditable(rowIndex, columnIndex);
		}

		@Override
		public Object getValueAt(int rowIndex, int columnIndex) {
			return model.getValueAt(rowIndex, columnIndex);
		}

		@Override
		public Object getColumnValueForRow(T t, int columnIndex) {
			return model.getColumnValueForRow(t, columnIndex);
		}

		@Override
		public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
			model.setValueAt(aValue, rowIndex, columnIndex);
		}
	}

	/**
	 * Subclass that delegates filter methods to the wrapped model.
	 */
	private class FilterModelPassThrough extends FilterModelAdapter {

		private final RowObjectFilterModel<T> filterModel;

		FilterModelPassThrough(RowObjectFilterModel<T> model) {
			super(model);
			filterModel = model;
		}

		@Override
		public int getUnfilteredRowCount() {
			return filterModel.getUnfilteredRowCount();
		}

		@Override
		public int getModelRow(int viewRow) {
			return filterModel.getModelRow(viewRow);
		}

		@Override
		public int getViewRow(int modelRow) {
			return filterModel.getViewRow(modelRow);
		}

		@Override
		public boolean isFiltered() {
			return filterModel.isFiltered();
		}

		@Override
		public void setTableFilter(TableFilter<T> filter) {
			filterModel.setTableFilter(filter);
		}

		@Override
		public List<T> getUnfilteredData() {
			return filterModel.getUnfilteredData();
		}
	}

	private class SelectionStorageHelper implements SelectionStorage<T> {
		private List<T> lastSelectedObjects = new ArrayList<>();

		@Override
		public List<T> getLastSelectedObjects() {
			return lastSelectedObjects;
		}

		@Override
		public void setLastSelectedObjects(List<T> lastSelectedObjects) {
			this.lastSelectedObjects = lastSelectedObjects;
		}

	}
}
