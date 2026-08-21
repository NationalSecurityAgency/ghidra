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
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;
import javax.swing.table.TableColumn;

import docking.widgets.table.GTableTextCellEditor;
import docking.widgets.table.threaded.ThreadedTableModelListener;
import generic.theme.GIcon;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.table.*;

/**
 * Provider for the defined strings table.
 */
public class DefinedStringsProvider extends ComponentProviderAdapter {

	public static final Icon ICON = new GIcon("icon.plugin.viewstrings.provider");

	private GhidraThreadedTablePanel<ProgramLocation> threadedTablePanel;
	private GhidraTableFilterPanel<ProgramLocation> filterPanel;
	private GhidraTable table;
	private DefinedStringsTableModel stringModel;
	private JComponent mainPanel;
	private Program currentProgram;
	private HelpLocation helpLocation;
	private AtomicReference<ProgramLocation> delayedShowProgramLocation = new AtomicReference<>();

	DefinedStringsProvider(DefinedStringsPlugin plugin) {
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
	public DefinedStringsContext getActionContext(MouseEvent event) {
		return new DefinedStringsContext(this, table, stringModel);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

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

		stringModel = new DefinedStringsTableModel(tool);

		threadedTablePanel = new GhidraThreadedTablePanel<>(stringModel, 1000);
		table = threadedTablePanel.getTable();
		table.setPreferredScrollableViewportSize(new Dimension(350, 150));
		table.getSelectionModel().addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				notifyContextChanged();
			}
		});

		stringModel.addTableModelListener(e -> {
			int rowCount = stringModel.getRowCount();
			int unfilteredCount = stringModel.getUnfilteredRowCount();

			setSubTitle("%d items%s".formatted(rowCount,
				rowCount != unfilteredCount ? " (of " + unfilteredCount + ")" : ""));
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
		TableColumn stringRepCol = table.getColumnModel()
				.getColumn(DefinedStringsTableModel.COLUMNS.STRING_REP_COL.ordinal());

		stringRepCol.setCellEditor(new StringRepCellEditor());

		table.installNavigation(tool);

		filterPanel = new GhidraTableFilterPanel<>(table, stringModel);
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(threadedTablePanel, BorderLayout.CENTER);
		panel.add(filterPanel, BorderLayout.SOUTH);

		String namePrefix = "Defined Strings";
		table.setAccessibleNamePrefix(namePrefix);
		filterPanel.setAccessibleNamePrefix(namePrefix);

		return panel;
	}

	private void notifyContextChanged() {
		tool.contextChanged(this);
	}

	void add(Data data) {
		if (isVisible()) {
			stringModel.addDataInstance(currentProgram, data);
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

	public DefinedStringsTableModel getModel() {
		return stringModel;
	}

	private void doShowProgramLocation(ProgramLocation pl) {
		ProgramLocation modelLocation = stringModel.findEquivProgramLocation(pl);
		if (modelLocation == null) {
			return;
		}

		int newRow = stringModel.getViewIndex(modelLocation);
		if (newRow < 0) {
			return;
		}

		table.selectRow(newRow);
		table.scrollToSelectedRow();
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
				boolean isSelected, int rowIndex, int columnIndex) {
			Data data = DataUtilities.getDataAtLocation(stringModel.getRowObject(rowIndex));
			if (data != null) {
				textField.setEditable(true);
				StringDataInstance sdi = StringDataInstance.getStringDataInstance(data);
				if (sdi.isShowTranslation() && sdi.getTranslatedValue() != null) {
					textField.setText(sdi.getTranslatedValue());
				}
				else {
					textField.setText(sdi.getStringValue());
				}
			}
			else {
				textField.setEditable(false);
				textField.setText("unsupported");
			}
			return textField;
		}
	}
}
