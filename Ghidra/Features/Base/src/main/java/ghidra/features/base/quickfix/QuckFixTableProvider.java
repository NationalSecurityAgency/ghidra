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
package ghidra.features.base.quickfix;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.table.TableModel;

import docking.*;
import docking.action.ToggleDockingAction;
import docking.action.builder.ActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.ThreadedTableModel;
import generic.theme.GIcon;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramTask;
import ghidra.util.HelpLocation;
import ghidra.util.table.*;
import ghidra.util.table.actions.DeleteTableRowAction;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/**
 * Component Provider for displaying lists of {@link QuickFix}s and the actions to execute them
 * in bulk or individually. 
 */
public class QuckFixTableProvider extends ComponentProvider {
	private static final Icon EXECUTE_ICON = new GIcon("icon.base.plugin.quickfix.done");
	private JComponent component;
	private QuickFixTableModel tableModel;
	private GhidraThreadedTablePanel<QuickFix> threadedPanel;
	private GhidraTableFilterPanel<QuickFix> tableFilterPanel;
	private GhidraTable table;
	private ToggleDockingAction toggleAutoDeleteAction;
	private boolean autoDelete;

	public QuckFixTableProvider(PluginTool tool, String title, String owner, Program program,
			TableDataLoader<QuickFix> loader) {
		super(tool, title, owner);
		setIcon(new GIcon("icon.plugin.table.service"));
		setTransient();
		setTitle(title);

		tableModel = new QuickFixTableModel(program, title, tool, loader);
		tableModel.addInitialLoadListener(b -> tableLoaded(b, loader));

		component = buildMainPanel();

		createActions(owner);

		tableModel.addTableModelListener(e -> tableDataChanged());
	}

	protected void tableLoaded(boolean wasCancelled, TableDataLoader<QuickFix> loader) {
		// used by subclasses
	}

	private void updateSubTitle() {
		StringBuilder builder = new StringBuilder();
		builder.append(" ");
		int count = tableModel.getUnfilteredRowCount();
		if (count > 0) {
			builder.append("(");
			builder.append(count);
			builder.append(count == 1 ? " item)" : " items)");
		}
		setSubTitle(builder.toString());
	}

	protected void createActions(String owner) {
		new ActionBuilder("Apply Action", owner)
				.popupMenuPath("Apply Selected Items(s)")
				.popupMenuIcon(EXECUTE_ICON)
				.popupMenuGroup("aaa")
				.toolBarIcon(EXECUTE_ICON)
				.description("Applies the selected items")
				.helpLocation(new HelpLocation("Search", "Apply_Selected"))
				.keyBinding("ctrl e")
				.withContext(QuickFixActionContext.class)
				.enabledWhen(c -> c.getSelectedRowCount() > 0)
				.onAction(this::applySelectedItems)
				.buildAndInstallLocal(this);

		toggleAutoDeleteAction = new ToggleActionBuilder("Toggle Auto Delete", owner)
				.popupMenuPath("Auto Delete Completed Items")
				.popupMenuGroup("settings")
				.helpLocation(new HelpLocation("Search", "Auto_Delete"))
				.description("If on, automatically remove completed items from the list")
				.onAction(this::toggleAutoDelete)
				.buildAndInstallLocal(this);

		addLocalAction(new SelectionNavigationAction(owner, table));

		GoToService service = dockingTool.getService(GoToService.class);
		if (service != null) {
			Navigatable navigatable = service.getDefaultNavigatable();
			addLocalAction(new MakeProgramSelectionAction(navigatable, owner, table, "bbb"));
		}
		DeleteTableRowAction deleteAction = new DeleteTableRowAction(table, owner, "bbb") {
			@Override
			public void actionPerformed(ActionContext context) {
				super.actionPerformed(context);
				updateSubTitle();
			}
		};
		addLocalAction(deleteAction);

	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		return new QuickFixActionContext();
	}

	private void tableDataChanged() {
		updateTitle();
	}

	private void updateTitle() {
		int rowCount = tableModel.getRowCount();
		int filteredRowCount = tableFilterPanel.getRowCount();
		setSubTitle("(" + filteredRowCount + " of " + rowCount + ")");
	}

	@Override
	public void closeComponent() {
		super.closeComponent();
		tableFilterPanel.dispose();
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	protected JPanel buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		threadedPanel = new GhidraThreadedTablePanel<>(tableModel) {
			protected GTable createTable(ThreadedTableModel<QuickFix, ?> model) {
				return new QuickFixGhidraTable(model);
			}
		};
		table = threadedPanel.getTable();
		table.getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			dockingTool.contextChanged(QuckFixTableProvider.this);
		});

		table.setActionsEnabled(true);
		table.installNavigation(dockingTool);

		panel.add(threadedPanel, BorderLayout.CENTER);
		panel.add(createFilterFieldPanel(), BorderLayout.SOUTH);
		panel.setPreferredSize(new Dimension(1000, 600));
		return panel;
	}

	private JPanel createFilterFieldPanel() {
		tableFilterPanel = new GhidraTableFilterPanel<>(table, tableModel);
		return tableFilterPanel;
	}

	public boolean isBusy(TableModel model) {

		if (!(model instanceof ThreadedTableModel)) {
			return false;
		}

		ThreadedTableModel<?, ?> threadedModel = (ThreadedTableModel<?, ?>) model;
		if (threadedModel.isBusy()) {
			return true;
		}
		return false;
	}

	private void applySelectedItems(QuickFixActionContext context) {
		List<QuickFix> selectedItems = tableFilterPanel.getSelectedItems();
		int nextIndex = selectedItems.size() == 1 ? table.getSelectedRow() : -1;

		applyItems(selectedItems);

		if (nextIndex >= 0) {
			int index = nextIndex + 1;
			if (index < table.getRowCount()) {
				table.selectRow(nextIndex + 1);
			}
		}

		if (autoDelete) {
			removeCompletedItems(selectedItems);
		}
		tableModel.fireTableDataChanged();
	}

	private void toggleAutoDelete(ActionContext context) {
		autoDelete = toggleAutoDeleteAction.isSelected();
		if (autoDelete) {
			removeCompletedItems(tableModel.getModelData());
		}
	}

	private void removeCompletedItems(List<QuickFix> items) {
		List<QuickFix> toDelete = new ArrayList<>();
		for (QuickFix item : items) {
			if (item.getStatus() == QuickFixStatus.DONE) {
				toDelete.add(item);
			}
		}

		for (QuickFix quickFix : toDelete) {
			tableModel.removeObject(quickFix);
		}
	}

	private void applyItems(List<QuickFix> quickFixList) {
		Program program = tableModel.getProgram();
		ProgramTask task = new ApplyItemsTask(program, getTaskTitle(), quickFixList);
		TaskLauncher.launch(task);
	}

	public void executeAll() {
		List<QuickFix> allItems = tableModel.getModelData();
		applyItems(allItems);
		tableModel.fireTableDataChanged();
	}

	protected String getTaskTitle() {
		return "Applying Items";
	}

	public void programClosed(Program program) {
		if (program == tableModel.getProgram()) {
			this.closeComponent();
		}
	}

	private static class ApplyItemsTask extends ProgramTask {

		private List<QuickFix> quickFixList;

		public ApplyItemsTask(Program program, String title, List<QuickFix> quickFixList) {
			super(program, title, true, true, true);
			this.quickFixList = quickFixList;
		}

		@Override
		protected void doRun(TaskMonitor monitor) {
			for (QuickFix quickFix : quickFixList) {
				quickFix.performAction();
			}
		}

	}

	/**
	 * Returns the table model.
	 * @return the table model
	 */
	public QuickFixTableModel getTableModel() {
		return tableModel;
	}

	/**
	 * Sets the selected rows in the table
	 * @param start the index of the first row to select
	 * @param end the index of the last row to select
	 */
	public void setSelection(int start, int end) {
		table.setRowSelectionInterval(start, end);
	}

	/**
	 * Returns the selected row in the table
	 * @return the selected row in the table
	 */
	public int getSelectedRow() {
		return table.getSelectedRow();
	}

	/**
	 * Applies all the selected items.
	 */
	public void applySelected() {
		applySelectedItems(null);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================
	private class QuickFixActionContext extends DefaultActionContext {
		QuickFixActionContext() {
			super(QuckFixTableProvider.this, table);
		}

		public int getSelectedRowCount() {
			return table.getSelectedRowCount();
		}
	}

	private class QuickFixGhidraTable extends GhidraTable {
		boolean fromSelectionChange = false;

		public QuickFixGhidraTable(ThreadedTableModel<QuickFix, ?> model) {
			super(model);
		}

		@Override
		public void navigate(int row, int column) {
			if (!doSpecialNavigate(row)) {
				super.navigate(row, column);
			}
		}

		@Override
		protected void navigateOnCurrentSelection(int row, int column) {
			fromSelectionChange = true;
			try {
				super.navigateOnCurrentSelection(row, column);
			}
			finally {
				fromSelectionChange = false;
			}
		}

		private boolean doSpecialNavigate(int row) {
			QuickFix quickFix = tableFilterPanel.getRowObject(row);
			return quickFix.navigateSpecial(dockingTool, fromSelectionChange);
		}
	}

}
