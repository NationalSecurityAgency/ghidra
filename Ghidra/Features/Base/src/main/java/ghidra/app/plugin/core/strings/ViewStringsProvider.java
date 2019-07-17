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
package ghidra.app.plugin.core.strings;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;

import javax.swing.*;
import javax.swing.table.TableColumn;

import docking.ActionContext;
import docking.widgets.table.GTableTextCellEditor;
import docking.widgets.table.threaded.ThreadedTableModelListener;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.table.*;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

/**
 * Provider for the defined strings table.
 */
public class ViewStringsProvider extends ComponentProviderAdapter {

	public static final ImageIcon ICON = ResourceManager.loadImage("images/dataW.gif");

	private GhidraThreadedTablePanel<ProgramLocation> threadedTablePanel;
	private GhidraTableFilterPanel<ProgramLocation> filterPanel;
	private GhidraTable table;
	private ViewStringsTableModel stringModel;
	private JComponent mainPanel;
	private Program currentProgram;
	private HelpLocation helpLocation;
	private AtomicReference<ProgramLocation> delayedShowProgramLocation = new AtomicReference<>();

	ViewStringsProvider(ViewStringsPlugin plugin) {
		super(plugin.getTool(), "Defined Strings", plugin.getName());
		mainPanel = createWorkPanel();
		setIcon(ICON);
		helpLocation = new HelpLocation(plugin.getName(), plugin.getName());
		addToTool();
	}

	@Override
	public void componentHidden() {
		stringModel.reload(null);
	}

	@Override
	public void componentShown() {
		stringModel.reload(currentProgram);
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		return new ViewStringsContext(this, table);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	/*
	 * @see ghidra.framework.docking.HelpTopic#getHelpLocation()
	 */
	@Override
	public HelpLocation getHelpLocation() {
		return helpLocation;
	}

	void setProgram(Program program) {
		if (program == currentProgram) {
			return;
		}
		currentProgram = program;
		delayedShowProgramLocation.set(null);
		if (isVisible()) {
			stringModel.reload(program);
		}
	}

	void dispose() {
		currentProgram = null;
		removeFromTool();
		threadedTablePanel.dispose();
		filterPanel.dispose();
	}

	private JComponent createWorkPanel() {

		stringModel = new ViewStringsTableModel(tool);

		threadedTablePanel = new GhidraThreadedTablePanel<>(stringModel, 1000);
		table = threadedTablePanel.getTable();
		table.setName("DataTable");
		table.setPreferredScrollableViewportSize(new Dimension(350, 150));
		table.getSelectionModel().addListSelectionListener(e -> notifyContextChanged());

		stringModel.addTableModelListener(e -> {
			int rowCount = stringModel.getRowCount();
			int unfilteredCount = stringModel.getUnfilteredRowCount();

			setSubTitle("" + rowCount + " items" +
				(rowCount != unfilteredCount ? " (of " + unfilteredCount + ")" : ""));
		});

		stringModel.addThreadedTableModelListener(new ThreadedTableModelListener() {

			@Override
			public void loadingStarted() {
				// ignore
			}

			@Override
			public void loadingFinished(boolean wasCancelled) {
				// loadingFinished gets called when the table is empty
				// and then when it finishes loading.
				// Only de-queue the delayedProgramLocation if we have records in the model.
				if (stringModel.getRowCount() != 0) {
					ProgramLocation delayedProgLoc = delayedShowProgramLocation.getAndSet(null);
					if (delayedProgLoc != null) {
						doShowProgramLocation(delayedProgLoc);
					}
				}
			}

			@Override
			public void loadPending() {
				// ignore
			}
		});
		TableColumn stringRepCol = table.getColumnModel().getColumn(
			ViewStringsTableModel.COLUMNS.STRING_REP_COL.ordinal());

		stringRepCol.setCellEditor(new StringRepCellEditor());

		GoToService goToService = tool.getService(GoToService.class);
		table.installNavigation(goToService, goToService.getDefaultNavigatable());

		filterPanel = new GhidraTableFilterPanel<>(table, stringModel);

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(threadedTablePanel, BorderLayout.CENTER);
		panel.add(filterPanel, BorderLayout.SOUTH);

		return panel;
	}

	private void notifyContextChanged() {
		tool.contextChanged(this);
	}

	ProgramSelection selectData() {
		return table.getProgramSelection();
	}

	void add(Data data) {
		if (isVisible()) {
			stringModel.addDataInstance(currentProgram, data, TaskMonitor.DUMMY);
		}
	}

	void remove(Address addr) {
		if (isVisible()) {
			stringModel.removeDataInstanceAt(addr);
		}
	}

	void remove(Address start, Address end) {
		if (isVisible()) {
			long count = end.subtract(start);
			for (long offset = 0; offset < count; offset++) {
				stringModel.removeDataInstanceAt(start.add(offset));
			}
		}
	}

	void reload() {
		if (isVisible()) {
			stringModel.reload();
		}
	}

	public GhidraTable getTable() {
		return table;
	}

	public ViewStringsTableModel getModel() {
		return stringModel;
	}

	private void doShowProgramLocation(ProgramLocation loc) {
		ProgramLocation realLoc = stringModel.findEquivProgramLocation(loc);
		if (realLoc != null) {
			int rowIndex = stringModel.getViewIndex(realLoc);
			if (rowIndex >= 0) {
				table.selectRow(rowIndex);
				table.scrollToSelectedRow();
			}
			else {
				getTool().setStatusInfo(
					"String at " + realLoc.getAddress() + " is filtered out of table view", false);
			}
		}
	}

	public void showProgramLocation(ProgramLocation loc) {
		if (loc == null) {
			return;
		}

		if (!stringModel.isBusy()) {
			doShowProgramLocation(loc);
		}
		else {
			delayedShowProgramLocation.set(loc);
		}
	}

	public int getSelectedRowCount() {
		return table.getSelectedRowCount();
	}

	public Data getSelectedData() {
		int selectedRow = table.getSelectedRow();
		if (selectedRow < 0) {
			return null;
		}
		ProgramLocation location = stringModel.getRowObject(selectedRow);
		return DataUtilities.getDataAtLocation(location);
	}

	public List<Data> getSelectedDataList(Predicate<Data> filter) {
		List<Data> list = new ArrayList<>();
		int[] selectedRows = table.getSelectedRows();
		for (int row : selectedRows) {
			ProgramLocation location = stringModel.getRowObject(row);
			Data data = DataUtilities.getDataAtLocation(location);
			if (passesFilter(data, filter)) {
				list.add(data);
			}
		}
		return list;
	}

	public List<ProgramLocation> getSelectedDataLocationList(Predicate<Data> filter) {
		List<ProgramLocation> result = new ArrayList<>();
		int[] selectedRows = table.getSelectedRows();
		for (int row : selectedRows) {
			ProgramLocation location = stringModel.getRowObject(row);
			Data data = DataUtilities.getDataAtLocation(location);
			if (passesFilter(data, filter)) {
				result.add(location);
			}
		}
		return result;
	}

	private boolean passesFilter(Data data, Predicate<Data> filter) {
		if (data == null) {
			return false;
		}
		if (filter == null) {
			return true;
		}
		return filter.test(data);
	}

	public Program getProgram() {
		return currentProgram;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * Table cell editor that swaps the editing value to be the raw string value instead of the
	 * formatted representation.
	 * <p>
	 * This causes the cell to be displayed as the formatted representation and then when the user
	 * double clicks to start editing mode, it swaps to non-formatted version.
	 */
	private class StringRepCellEditor extends GTableTextCellEditor {

		private JTextField textField;

		StringRepCellEditor() {
			super(new JTextField());
			textField = (JTextField) super.getComponent();
		}

		@Override
		public Object getCellEditorValue() {
			return textField.getText();
		}

		@Override
		public Component getTableCellEditorComponent(JTable jTable, Object value,
				boolean isSelected, int row, int column) {
			if (value instanceof StringDataInstance) {
				textField.setEditable(true);
				StringDataInstance sdi = (StringDataInstance) value;
				if (sdi.isShowTranslation() && sdi.getTranslatedValue() != null) {
					textField.setText(sdi.getTranslatedValue());
				}
				else {
					textField.setText(sdi.getStringValue());
				}
			}
			else {
				textField.setText("");
				textField.setEditable(false);
			}
			return textField;
		}
	}
}
