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
package ghidra.app.tablechooser;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;
import javax.swing.table.TableCellRenderer;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingAction;
import docking.widgets.table.*;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.app.nav.Navigatable;
import ghidra.app.nav.NavigatableRemovalListener;
import ghidra.app.services.GoToService;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.table.*;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import ghidra.util.task.TaskMonitor;
import utility.function.Callback;

/**
 * Dialog to show a table of items.  If the dialog is constructed with a non-null
 * {@link TableChooserExecutor}, then a button will be placed in the dialog, allowing the user
 * to perform the action defined by the executor.
 *
 * <p>Each button press will use the selected items as the items to be processed.  While the
 * items are scheduled to be processed, they will still be in the table, painted light gray.
 * Attempting to reschedule any of these pending items will have no effect.   Each time the
 * button is pressed, a new {@link SwingWorker} is created, which will put the processing into
 * a background thread.   Further, by using multiple workers, the work will be performed in
 * parallel.
 */
public class TableChooserDialog extends DialogComponentProvider
		implements NavigatableRemovalListener {

	// thread-safe data structures
	private WeakSet<ExecutorSwingWorker> workers =
		WeakDataStructureFactory.createCopyOnReadWeakSet();
	private Set<AddressableRowObject> sharedPending = ConcurrentHashMap.newKeySet();

	private final TableChooserExecutor executor;
	private WrappingCellRenderer wrappingRenderer = new WrappingCellRenderer();

	private GhidraTable table;
	private TableChooserTableModel model;
	private final Program program;
	private final PluginTool tool;
	private Navigatable navigatable;

	private Callback closedCallback = Callback.dummy();

	public TableChooserDialog(PluginTool tool, TableChooserExecutor executor, Program program,
			String title, Navigatable navigatable, boolean isModal) {

		super(title, isModal, true, true, true);
		this.tool = tool;
		this.executor = executor;
		this.program = program;
		this.navigatable = navigatable;
		addWorkPanel(buildMainPanel());
		if (executor != null) {
			addOKButton();
			setOkButtonText(executor.getButtonName());
		}
		addDismissButton();
		createActions();
		setOkEnabled(false);
	}

	public TableChooserDialog(PluginTool tool, TableChooserExecutor executor, Program program,
			String title, Navigatable navigatable) {
		this(tool, executor, program, title, navigatable, false);
	}

	private JPanel buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		createTableModel();
		TableChooserDialogPanel tablePanel = new TableChooserDialogPanel(model);

		table = tablePanel.getTable();
		GoToService goToService = tool.getService(GoToService.class);
		if (goToService != null) {
			navigatable = navigatable == null ? goToService.getDefaultNavigatable() : navigatable;
			navigatable.addNavigatableListener(this);
			table.installNavigation(goToService, navigatable);
		}
		table.getSelectionModel()
				.addListSelectionListener(e -> setOkEnabled(table.getSelectedRowCount() > 0));

		GhidraTableFilterPanel<AddressableRowObject> filterPanel =
			new GhidraTableFilterPanel<>(table, model);
		panel.add(tablePanel, BorderLayout.CENTER);
		panel.add(filterPanel, BorderLayout.SOUTH);
		return panel;
	}

	/**
	 * Sets the given listener that will get notified when this dialog is closed
	 * @param callback the callback to notify
	 */
	public void setClosedListener(Callback callback) {
		Swing.runNow(() -> closedCallback = Callback.dummyIfNull(callback));
	}

	/**
	 * Adds the given object to this dialog.  This method can be called from any thread.
	 *
	 * @param rowObject the object to add
	 */
	public void add(AddressableRowObject rowObject) {
		model.addObject(rowObject);
	}

	/**
	 * Removes the given object from this dialog.  Nothing will happen if the given item is not
	 * in this dialog.  This method can be called from any thread.
	 *
	 * @param rowObject the object to remove
	 */
	public void remove(AddressableRowObject rowObject) {
		model.removeObject(rowObject);
	}

	private void createTableModel() {

		// note: the task monitor is installed later when this model is added to the threaded panel
		Swing.runNow(() -> model = new TableChooserTableModel("Test", tool, program, null));
	}

	private void createActions() {
		String owner = getClass().getSimpleName();

		DockingAction selectAction = new MakeProgramSelectionAction(owner, table) {
			@Override
			protected ProgramSelection makeSelection(ActionContext context) {
				ProgramSelection selection = table.getProgramSelection();
				if (navigatable != null) {
					navigatable.goTo(program,
						new ProgramLocation(program, selection.getMinAddress()));
					navigatable.setSelection(selection);
					navigatable.requestFocus();
				}
				return selection;
			}
		};

		DockingAction selectionNavigationAction = new SelectionNavigationAction(owner, table);
		selectionNavigationAction
				.setHelpLocation(new HelpLocation(HelpTopics.SEARCH, "Selection_Navigation"));

		addAction(selectAction);
		addAction(selectionNavigationAction);
	}

	public void show() {
		tool.showDialog(this);
	}

	@Override
	public void close() {
		super.close();
		if (navigatable != null) {
			navigatable.removeNavigatableListener(this);
		}
		dispose();
	}

	@Override
	protected void dialogClosed() {
		closedCallback.call();
	}

	@Override
	protected void okCallback() {

		List<AddressableRowObject> rowObjects = getSelectedRowObjects();
		rowObjects.removeAll(sharedPending); // only keep selected items not being processed
		if (rowObjects.isEmpty()) {
			return;
		}

		clearSelection(); // prevent odd behavior with selection around as the table changes
		sharedPending.addAll(rowObjects);

		TaskMonitor monitor = getTaskMonitorComponent();
		ExecutorSwingWorker worker = new ExecutorSwingWorker(rowObjects, monitor);
		workers.add(worker);

		showProgressBar("Working", true, true, 0);
		worker.execute();
	}

	private void workerDone(ExecutorSwingWorker worker) {
		workers.remove(worker);
		if (workers.isEmpty()) {
			hideTaskMonitorComponent();
		}
	}

	public boolean isBusy() {
		for (ExecutorSwingWorker worker : workers) {
			if (!worker.isDone()) {
				return true;
			}
		}

		return model.isBusy();
	}

	private void doExecute(List<AddressableRowObject> rowObjects, TaskMonitor monitor) {

		monitor.initialize(rowObjects.size());

		try {
			List<AddressableRowObject> deleted = doProcessRowsInTransaction(rowObjects, monitor);

			for (AddressableRowObject rowObject : deleted) {
				model.removeObject(rowObject);
			}
		}
		finally {
			// Note: the code below this comment needs to happen, even if the monitor is cancelled
			sharedPending.removeAll(rowObjects);
			model.fireTableDataChanged();
			setStatusText("");
		}
	}

	private List<AddressableRowObject> doProcessRows(List<AddressableRowObject> rowObjects,
			TaskMonitor monitor) {

		List<AddressableRowObject> deleted = new ArrayList<>();
		for (AddressableRowObject rowObject : rowObjects) {
			if (monitor.isCancelled()) {
				break;
			}

			if (!model.containsObject(rowObject)) {
				// this implies the item has been programmatically removed
				monitor.incrementProgress(1);
				continue;
			}

			monitor.setMessage("Processing item at address " + rowObject.getAddress());
			if (executor.execute(rowObject)) {
				deleted.add(rowObject);
			}

			monitor.incrementProgress(1);
			table.repaint(); // in case the data is updated while processing
		}

		return deleted;
	}

	private List<AddressableRowObject> doProcessRowsInTransaction(
			List<AddressableRowObject> rowObjects, TaskMonitor monitor) {

		int tx = program.startTransaction("Table Chooser: " + getTitle());
		try {
			return doProcessRows(rowObjects, monitor);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	public void addCustomColumn(ColumnDisplay<?> columnDisplay) {
		Swing.runNow(() -> model.addCustomColumn(columnDisplay));
	}

	/**
	 * Sets the default sorted column for this dialog.
	 *
	 * <P>This method should be called after all custom columns have been added via
	 * {@link #addCustomColumn(ColumnDisplay)}.
	 *
	 * @param index the view's 0-based column index
	 * @see #setSortState(TableSortState)
	 * @throws IllegalArgumentException if an invalid column is requested for sorting
	 */
	public void setSortColumn(int index) {
		setSortState(TableSortState.createDefaultSortState(index));
	}

	/**
	 * Sets the column sort state for this dialog.   The {@link TableSortState} allows for
	 * combinations of sorted columns in ascending or descending order.
	 *
	 * <P>This method should be called after all custom columns have been added via
	 * {@link #addCustomColumn(ColumnDisplay)}.
	 *
	 * @param state the sort state
	 * @see #setSortColumn(int)
	 * @throws IllegalArgumentException if an invalid column is requested for sorting
	 */
	public void setSortState(TableSortState state) {
		AtomicReference<IllegalArgumentException> ref = new AtomicReference<>();
		Swing.runNow(() -> {
			try {
				model.setTableSortState(state);
			}
			catch (IllegalArgumentException e) {
				ref.set(e);
			}
		});
		IllegalArgumentException exception = ref.get();
		if (exception != null) {
			// use a new exception so the stack trace points to this class, not the runnable above
			throw new IllegalArgumentException(exception);
		}
	}

	@Override
	public void navigatableRemoved(Navigatable nav) {
		close();
	}

	public void setMessage(String message) {
		setStatusText(message);
	}

	public int getRowCount() {
		return model.getRowCount();
	}

	public void clearSelection() {
		Swing.runNow(() -> table.clearSelection());
	}

	public void selectRows(int... rows) {

		Swing.runNow(() -> {
			ListSelectionModel selectionModel = table.getSelectionModel();
			for (int row : rows) {
				selectionModel.addSelectionInterval(row, row);
			}
		});
	}

	public int[] getSelectedRows() {
		int[] selectedRows = table.getSelectedRows();
		return selectedRows;
	}

	public List<AddressableRowObject> getSelectedRowObjects() {
		int[] selectedRows = table.getSelectedRows();
		List<AddressableRowObject> rowObjects = model.getRowObjects(selectedRows);
		return rowObjects;
	}

	public void dispose() {
		table.dispose();
		workers.forEach(w -> w.cancel(true));
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class TableChooserDialogPanel extends GhidraThreadedTablePanel<AddressableRowObject> {

		public TableChooserDialogPanel(ThreadedTableModel<AddressableRowObject, ?> model) {
			super(model, 50, 2000);
		}

		@Override
		protected GTable createTable(ThreadedTableModel<AddressableRowObject, ?> tm) {
			return new TableChooserDialogGhidraTable(tm);
		}
	}

	private class TableChooserDialogGhidraTable extends GhidraTable {

		public TableChooserDialogGhidraTable(ThreadedTableModel<AddressableRowObject, ?> tm) {
			super(tm);
		}

		@Override
		public TableCellRenderer getCellRenderer(int row, int col) {
			TableCellRenderer tableRenderer = super.getCellRenderer(row, col);
			wrappingRenderer.setDelegate(tableRenderer);
			return wrappingRenderer;
		}
	}

	private class WrappingCellRenderer extends GhidraTableCellRenderer {

		private Color pendingColor = new Color(192, 192, 192, 75);
		private TableCellRenderer delegate;

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			Component superRenderer;
			if (delegate instanceof GTableCellRenderer) {
				superRenderer = super.getTableCellRendererComponent(data);
			}
			else {
				superRenderer = super.getTableCellRendererComponent(data.getTable(),
					data.getValue(), data.isSelected(), data.hasFocus(), data.getRowViewIndex(),
					data.getColumnViewIndex());
			}

			AddressableRowObject ro = (AddressableRowObject) data.getRowObject();
			if (sharedPending.contains(ro)) {
				superRenderer.setBackground(pendingColor);
				superRenderer.setForeground(data.getTable().getSelectionForeground());
				superRenderer.setForeground(Color.BLACK);
			}

			return superRenderer;
		}

		void setDelegate(TableCellRenderer delegate) {
			this.delegate = delegate;
		}
	}

	/**
	 * Runs our work off the Swing thread, so that the GUI updates as the task is being executed
	 */
	private class ExecutorSwingWorker extends SwingWorker<Object, Object> {

		private final TaskMonitor monitor;
		private List<AddressableRowObject> rowObjects;

		ExecutorSwingWorker(List<AddressableRowObject> rowObjects, TaskMonitor monitor) {
			this.rowObjects = rowObjects;
			this.monitor = monitor;
		}

		@Override
		protected Object doInBackground() throws Exception {
			doExecute(rowObjects, monitor);
			return null;
		}

		@Override
		protected void done() {
			workerDone(this);
		}

		@Override
		public String toString() {
			return rowObjects.toString();
		}
	}
}
