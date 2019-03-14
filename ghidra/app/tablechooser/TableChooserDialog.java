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

import java.awt.BorderLayout;
import java.util.*;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import docking.*;
import docking.action.*;
import ghidra.app.nav.Navigatable;
import ghidra.app.nav.NavigatableRemovalListener;
import ghidra.app.services.GoToService;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.table.*;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

public class TableChooserDialog extends DialogComponentProvider implements
		NavigatableRemovalListener {

	private final TableChooserExecutor executor;
	private Set<ExecutorSwingWorker> workers = new HashSet<ExecutorSwingWorker>();

	private GhidraTable table;
	private TableChooserTableModel model;
	private final Program program;
	private final PluginTool tool;
	private Navigatable navigatable;

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
		GhidraThreadedTablePanel<AddressableRowObject> tablePanel =
			new GhidraThreadedTablePanel<AddressableRowObject>(model, 50, 2000);

		table = tablePanel.getTable();
		GoToService goToService = tool.getService(GoToService.class);
		if (goToService != null) {
			navigatable = navigatable == null ? goToService.getDefaultNavigatable() : navigatable;
			navigatable.addNavigatableListener(this);
			table.installNavigation(goToService, navigatable);
		}
		table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent e) {
				setOkEnabled(table.getSelectedRowCount() > 0);
			}
		});

		GhidraTableFilterPanel<AddressableRowObject> filterPanel =
			new GhidraTableFilterPanel<AddressableRowObject>(table, model);
		panel.add(tablePanel, BorderLayout.CENTER);
		panel.add(filterPanel, BorderLayout.SOUTH);
		return panel;
	}

	public void add(AddressableRowObject rowObject) {
		model.addObject(rowObject);
	}

	private void createTableModel() {
		try {
			SwingUtilities.invokeAndWait(new Runnable() {
				@Override
				public void run() {
					model = new TableChooserTableModel("Test", tool, program, null /* set later*/);
				}
			});
		}
		catch (Exception e) {
			Msg.showError(this, null, "Error Creating Table", "Error Creating Table", e);
		}
	}

	private void createActions() {
		String owner = getClass().getSimpleName();
		DockingAction selectAction = new DockingAction("Make Selection", owner, false) {
			@Override
			public void actionPerformed(ActionContext context) {
				makeSelection();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return table.getSelectedRowCount() != 0;
			}
		};
		selectAction.setDescription("Make a selection using selected rows");
		selectAction.setEnabled(true);
		Icon icon = ResourceManager.loadImage("images/text_align_justify.png");
		selectAction.setToolBarData(new ToolBarData(icon));
		selectAction.setPopupMenuData(new MenuData(new String[] { "Make Selection" }, icon));
		selectAction.setHelpLocation(new HelpLocation(HelpTopics.SEARCH, "Make_Selection"));

		DockingAction selectionNavigationAction = new SelectionNavigationAction(owner, table);
		selectionNavigationAction.setHelpLocation(new HelpLocation(HelpTopics.SEARCH,
			"Selection_Navigation"));

		addAction(selectAction);
		addAction(selectionNavigationAction);
	}

	private void makeSelection() {
		ProgramSelection selection = table.getProgramSelection();
		if (program == null || program.isClosed() || selection.getNumAddresses() == 0) {
			return;
		}
		if (navigatable != null) {
			navigatable.goTo(program, new ProgramLocation(program, selection.getMinAddress()));
			navigatable.setSelection(selection);
			navigatable.requestFocus();
		}
	}

	public void show() {
		DockingWindowManager manager = DockingWindowManager.getActiveInstance();
		tool.showDialog(this, manager.getMainWindow());
	}

	@Override
	public void close() {
		super.close();
		if (navigatable != null) {
			navigatable.removeNavigatableListener(this);
		}
	}

	@Override
	protected void okCallback() {

		TaskMonitor monitor = showTaskMonitorComponent(executor.getButtonName(), true, true);

		try {
			ExecutorSwingWorker worker = new ExecutorSwingWorker(monitor);
			worker.execute();
			workers.add(worker);
		}
		finally {
			hideTaskMonitorComponent();
		}
	}

	public boolean isBusy() {
		ExecutorSwingWorker[] threadSafeArray =
			workers.toArray(new ExecutorSwingWorker[workers.size()]);
		for (ExecutorSwingWorker worker : threadSafeArray) {
			if (!worker.isDone()) {
				return true;
			}
		}
		return false;
	}

	private void doExecute(TaskMonitor monitor) {
		int[] selectedRows = table.getSelectedRows();

		monitor.initialize(selectedRows.length);

		List<AddressableRowObject> deletedRowObjects = new ArrayList<AddressableRowObject>();
		for (int selectedRow : selectedRows) {
			if (monitor.isCancelled()) {
				return;
			}

			AddressableRowObject rowObject = model.getRowObject(selectedRow);

			monitor.setMessage("Processing item at address " + rowObject.getAddress());

			if (executor.execute(rowObject)) {
				deletedRowObjects.add(rowObject);
			}

			monitor.incrementProgress(1);
			table.repaint(); // in case the data is updated while processing
		}

		for (AddressableRowObject addressableRowObject : deletedRowObjects) {
			model.removeObject(addressableRowObject);
		}

		model.fireTableDataChanged();
		setStatusText("");
	}

	public void addCustomColumn(ColumnDisplay<?> columnDisplay) {
		model.addCustomColumn(columnDisplay);
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

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * Runs our work off the Swing thread, so that the GUI updates as the task is being 
	 * executed.
	 */
	private class ExecutorSwingWorker extends SwingWorker<Object, Object> {

		private final TaskMonitor monitor;

		ExecutorSwingWorker(TaskMonitor monitor) {
			this.monitor = monitor;
		}

		@Override
		protected Object doInBackground() throws Exception {
			doExecute(monitor);
			return null;
		}

		@Override
		protected void done() {
			workers.remove(this);
		}
	}
}
