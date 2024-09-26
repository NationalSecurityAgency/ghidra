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
package ghidra.app.plugin.core.functionwindow;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.MouseEvent;
import java.util.*;

import javax.swing.*;
import javax.swing.table.*;

import docking.ActionContext;
import docking.DefaultActionContext;
import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import generic.theme.GIcon;
import ghidra.app.context.FunctionSupplierContext;
import ghidra.app.services.FunctionComparisonService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.HelpLocation;
import ghidra.util.table.*;
import ghidra.util.table.actions.MakeProgramSelectionAction;

/**
 * Provider that displays all functions in the selected program
 */
public class FunctionWindowProvider extends ComponentProviderAdapter {

	public static final Icon ICON = new GIcon("icon.plugin.functionwindow.provider");
	private static final Icon COMPARISON_ICON = new GIcon("icon.plugin.functioncompare.new");

	private FunctionWindowPlugin plugin;
	private GhidraTable functionTable;
	private FunctionTableModel functionModel;
	private JComponent mainPanel;

	private GhidraTableFilterPanel<FunctionRowObject> tableFilterPanel;
	private GhidraThreadedTablePanel<FunctionRowObject> threadedTablePanel;

	private DockingAction compareAction;

	/**
	 * Constructor
	 * 
	 * @param plugin the function window plugin
	 */
	FunctionWindowProvider(FunctionWindowPlugin plugin) {
		super(plugin.getTool(), "Functions Window", plugin.getName());
		setTitle("Functions");
		this.plugin = plugin;
		setIcon(ICON);
		setHelpLocation(new HelpLocation(plugin.getName(), plugin.getName()));
		tool = plugin.getTool();
		mainPanel = createWorkPanel();
		tool.addComponentProvider(this, false);
		createActions();
	}

	private void createActions() {
		addLocalAction(new SelectionNavigationAction(plugin.getName(), getTable()));
		addLocalAction(new MakeProgramSelectionAction(plugin, getTable()));
	}

	void createCompareAction() {
		compareAction = new ActionBuilder("Compare Functions", plugin.getName())
				.description("Create Function Comparison")
				.helpLocation(new HelpLocation("FunctionComparison", "Function_Comparison"))
				.toolBarIcon(COMPARISON_ICON)
				.toolBarGroup("Comparison")
				.enabledWhen(c -> functionTable.getSelectedRowCount() > 1)
				.onAction(c -> compareSelectedFunctions())
				.buildAndInstallLocal(this);
	}

	void removeCompareAction() {
		tool.removeLocalAction(this, compareAction);
	}

	private void compareSelectedFunctions() {
		Set<Function> functions = new HashSet<>();
		int[] selectedRows = functionTable.getSelectedRows();

		List<FunctionRowObject> functionRowObjects = functionModel.getRowObjects(selectedRows);
		for (FunctionRowObject functionRowObject : functionRowObjects) {
			Function rowFunction = functionRowObject.getFunction();
			functions.add(rowFunction);
		}

		FunctionComparisonService service = getTool().getService(FunctionComparisonService.class);
		service.createComparison(functions);
	}

	@Override
	public void componentHidden() {
		functionModel.reload(null);
	}

	@Override
	public void componentShown() {
		functionModel.reload(plugin.getProgram());
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		return new FunctionWindowActionContext();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	void programOpened(Program program) {
		if (isVisible()) {
			functionModel.reload(program);
		}
	}

	void programClosed() {
		functionModel.reload(null);
	}

	void showFunctions() {
		tool.showComponentProvider(this, true);
	}

	void dispose() {
		tool.removeComponentProvider(this);
		threadedTablePanel.dispose();
		tableFilterPanel.dispose();
	}

	void reload() {
		if (isVisible()) {
			functionModel.reload(plugin.getProgram());
		}
	}

	private JComponent createWorkPanel() {

		functionModel = new FunctionTableModel(plugin.getTool(), null);

		threadedTablePanel = new GhidraThreadedTablePanel<>(functionModel, 1000);

		functionTable = threadedTablePanel.getTable();
		functionTable.installNavigation(tool);
		functionTable.setAutoLookupColumn(FunctionTableModel.NAME_COL);
		functionTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
		functionTable.setPreferredScrollableViewportSize(new Dimension(350, 150));
		functionTable.setRowSelectionAllowed(true);
		functionTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		functionTable.getSelectionModel().addListSelectionListener(e -> tool.contextChanged(this));

		functionModel.addTableModelListener(e -> {
			int rowCount = functionModel.getRowCount();
			int unfilteredCount = functionModel.getUnfilteredRowCount();

			StringBuilder buffy = new StringBuilder();

			buffy.append(rowCount).append(" items");
			if (rowCount != unfilteredCount) {
				buffy.append(" (of ").append(unfilteredCount).append(" )");
			}

			setSubTitle(buffy.toString());
		});

		JTableHeader functionHeader = functionTable.getTableHeader();
		functionHeader.setUpdateTableInRealTime(true);
		setFunctionTableRenderer();

		tableFilterPanel = new GhidraTableFilterPanel<>(functionTable, functionModel);

		String namePrefix = "Functions";
		functionTable.setAccessibleNamePrefix(namePrefix);
		tableFilterPanel.setAccessibleNamePrefix(namePrefix);

		JPanel container = new JPanel(new BorderLayout());
		container.add(threadedTablePanel, BorderLayout.CENTER);
		container.add(tableFilterPanel, BorderLayout.SOUTH);
		return container;
	}

	private void setFunctionTableRenderer() {
		TableColumnModel columnModel = functionTable.getColumnModel();
		TableColumn column = columnModel.getColumn(FunctionTableModel.LOCATION_COL);
		column.setPreferredWidth(FunctionTableModel.LOCATION_COL_WIDTH);
	}

	void update(Function function) {
		if (!isVisible()) {
			return;
		}

		Set<Function> functions = getRelatedFunctions(function);
		for (Function f : functions) {
			functionModel.update(f);
		}
	}

	/**
	 * Gathers this function and any functions that thunk it
	 * @param f the function
	 * @return the related functions
	 */
	private Set<Function> getRelatedFunctions(Function f) {

		Program program = f.getProgram();
		FunctionManager functionManager = program.getFunctionManager();
		Set<Function> functions = new HashSet<>();
		Address[] addresses = f.getFunctionThunkAddresses(true);
		if (addresses != null) {
			for (Address a : addresses) {
				Function thunk = functionManager.getFunctionAt(a);
				if (thunk != null) {
					functions.add(thunk);
				}
			}
		}

		functions.add(f);
		return functions;
	}

	void functionAdded(Function function) {
		if (isVisible()) {
			functionModel.functionAdded(function);
		}
	}

	void functionRemoved(Function function) {
		if (isVisible()) {
			functionModel.functionRemoved(function);
		}
	}

	GhidraTable getTable() {
		return functionTable;
	}

	FunctionTableModel getModel() {
		return functionModel;
	}

	/**
	 * @see docking.ComponentProvider#getWindowSubMenuName()
	 */
	@Override
	public String getWindowSubMenuName() {
		return null;
	}

	/**
	 * @see docking.ComponentProvider#isTransient()
	 */
	@Override
	public boolean isTransient() {
		return false;
	}

	private class FunctionWindowActionContext extends DefaultActionContext
			implements FunctionSupplierContext {

		FunctionWindowActionContext() {
			super(FunctionWindowProvider.this, functionTable);
		}

		@Override
		public boolean hasFunctions() {
			return functionTable.getSelectedRowCount() > 0;
		}

		@Override
		public Set<Function> getFunctions() {
			Set<Function> functions = new HashSet<>();
			int[] selectedRows = functionTable.getSelectedRows();
			if (selectedRows.length == 0) {
				return Collections.emptySet();
			}
			List<FunctionRowObject> functionRowObjects = functionModel.getRowObjects(selectedRows);
			for (FunctionRowObject functionRowObject : functionRowObjects) {
				Function rowFunction = functionRowObject.getFunction();
				functions.add(rowFunction);
			}
			return functions;
		}
	}
}
