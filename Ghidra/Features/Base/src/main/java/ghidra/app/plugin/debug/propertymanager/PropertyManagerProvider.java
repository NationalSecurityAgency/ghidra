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
package ghidra.app.plugin.debug.propertymanager;

import java.awt.*;
import java.awt.event.MouseEvent;

import javax.swing.*;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.TableModelListener;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.services.MarkerSet;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.HelpLocation;
import ghidra.util.table.GhidraTable;
import resources.ResourceManager;

/**
 * PropertyManagerDialog
 */
public class PropertyManagerProvider extends ComponentProviderAdapter {

	protected static final ImageIcon ICON =
		ResourceManager.loadImage("images/document-properties.png");

	protected static final String DELETE_PROPERTIES_ACTION_NAME = "Delete Properties";

	private PropertyManagerPlugin plugin;
	private Program currentProgram;
	private AddressSetView restrictedView;

	private JTable table;
	private PropertyManagerTableModel model;
	private JPanel workPanel;

	private DockingAction deleteAction;

	private ListSelectionListener selectionListener;

	private TableModelListener tableModelListener;

	public PropertyManagerProvider(PropertyManagerPlugin plugin) {
		super(plugin.getTool(), "Manage Properties", plugin.getName());
		this.plugin = plugin;
		setIcon(ICON);
		setHelpLocation(new HelpLocation(plugin.getName(), "PropertyViewerPlugin"));
		setTitle("Manage Properties");
		addToTool();

		deleteAction = new DockingAction(DELETE_PROPERTIES_ACTION_NAME, plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				int row = table.getSelectedRow();
				if (row >= 0) {
					String propName = (String) model.getValueAt(row,
						PropertyManagerTableModel.PROPERTY_NAME_COLUMN);
					model.removeRow(row);
					Command cmd = new PropertyDeleteCmd(propName, restrictedView);
					PropertyManagerProvider.this.plugin.getTool().execute(cmd, currentProgram);
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return context.getContextObject() != null;
			}
		};
		deleteAction.setPopupMenuData(new MenuData(new String[] { "Delete" }));

		deleteAction.setHelpLocation(new HelpLocation(plugin.getName(), "DeleteProperties"));
		deleteAction.setEnabled(true);

		plugin.getTool().addLocalAction(this, deleteAction);
	}

	void dispose() {
		tool.removeComponentProvider(this);
	}

	void refresh() {
		ListSelectionModel selectionModel = table.getSelectionModel();
		selectionModel.removeListSelectionListener(selectionListener);
		model.removeTableModelListener(tableModelListener);
		this.currentProgram = plugin.getCurrentProgram();
		this.restrictedView = plugin.getCurrentSelection();

		String propName = null;
		int row = table.getSelectedRow();
		if (row >= 0) {
			propName =
				(String) model.getValueAt(row, PropertyManagerTableModel.PROPERTY_NAME_COLUMN);
			table.clearSelection();
		}

		model.update(currentProgram, restrictedView);

		if (propName != null) {
			int rows = model.getRowCount();
			for (int i = 0; i < rows; i++) {
				if (propName.equals(
					model.getValueAt(i, PropertyManagerTableModel.PROPERTY_NAME_COLUMN))) {
					table.getSelectionModel().setSelectionInterval(i, i);
					break;
				}
			}
		}
		model.addTableModelListener(tableModelListener);
		selectionModel.addListSelectionListener(selectionListener);
	}

	private JPanel createWorkPanel() {

		JPanel panel = new JPanel(new BorderLayout());

		model = new PropertyManagerTableModel();
		tableModelListener = e -> refreshMarkers();
		model.addTableModelListener(tableModelListener);

		table = new GhidraTable(model);
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		ListSelectionModel tlsm = table.getSelectionModel();
		selectionListener = e -> {
			ListSelectionModel lsm = (ListSelectionModel) e.getSource();
			refreshMarkers(table.getSelectedRow());
		};
		tlsm.addListSelectionListener(selectionListener);

		JScrollPane tablePane =
			new JScrollPane(table, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		tablePane.setPreferredSize(new Dimension(200, 100));

		// add min and max addresses to label above table
		panel.add(tablePane, BorderLayout.CENTER);

		return panel;
	}

	private void refreshMarkers() {
		refreshMarkers(table.getSelectedRow());
	}

	private void refreshMarkers(int row) {
		MarkerSet searchMarks = plugin.getSearchMarks();
		if (searchMarks == null) {
			return;
		}
		searchMarks.clearAll();
		if (row < 0) {
			return;
		}

		String propName =
			(String) model.getValueAt(row, PropertyManagerTableModel.PROPERTY_NAME_COLUMN);
		if (propName == null) {
			return;
		}
		Listing listing = currentProgram.getListing();
		CodeUnitIterator cui;
		if (restrictedView == null || restrictedView.isEmpty()) {
			cui = listing.getCodeUnitIterator(propName, true);
		}
		else {
			cui = listing.getCodeUnitIterator(propName, restrictedView, true);
		}
		while (cui.hasNext()) {
			CodeUnit cu = cui.next();
			searchMarks.add(cu.getMinAddress());
		}
	}

	@Override
	public void componentHidden() {
		table.clearSelection();
		plugin.disposeSearchMarks();
	}

	@Override
	public void componentShown() {
		if (table != null) {
			refresh();
		}
	}

	@Override
	public JComponent getComponent() {
		if (workPanel == null) {
			workPanel = createWorkPanel();
			refresh();
		}
		return workPanel;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (event != null && event.getSource() == table) {
			int row = table.getSelectedRow();
			if (row >= 0) {
				Rectangle rowBounds =
					table.getCellRect(row, PropertyManagerTableModel.PROPERTY_NAME_COLUMN, true);
				if (rowBounds.contains(event.getPoint())) {
					return createContext(rowBounds);
				}
			}
		}
		return null;
	}

	void programDeactivated() {
		currentProgram = null;
		if (model != null) {
			model.update(null, null);
		}
	}

	void programActivated(Program program) {
		this.currentProgram = program;
		if (model != null) {
			model.update(program, null);
		}
	}

	@Override
	public void componentActivated() {
		refresh();  // update the bookmarks
	}

}
