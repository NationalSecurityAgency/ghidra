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
import java.util.HashSet;
import java.util.Set;

import javax.swing.*;
import javax.swing.table.*;

import docking.ActionContext;
import docking.DefaultActionContext;
import generic.theme.GIcon;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.table.*;

/**
 * Provider that displays all functions in the selected program
 */
public class FunctionWindowProvider extends ComponentProviderAdapter {

	public static final Icon ICON = new GIcon("icon.plugin.functionwindow.provider");

	private FunctionWindowPlugin plugin;
	private GhidraTable functionTable;
	private FunctionTableModel functionModel;
	private JComponent mainPanel;

	private GhidraTableFilterPanel<FunctionRowObject> tableFilterPanel;
	private GhidraThreadedTablePanel<FunctionRowObject> threadedTablePanel;

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
		return new DefaultActionContext(this, functionTable);
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
		functionTable.setName("FunctionTable");

		GoToService goToService = tool.getService(GoToService.class);
		if (goToService != null) {
			functionTable.installNavigation(goToService, goToService.getDefaultNavigatable());
		}

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

		JPanel container = new JPanel(new BorderLayout());
		container.add(threadedTablePanel, BorderLayout.CENTER);
		container.add(tableFilterPanel, BorderLayout.SOUTH);
		return container;
	}

	ProgramSelection selectFunctions() {
		return functionTable.getProgramSelection();
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
}
