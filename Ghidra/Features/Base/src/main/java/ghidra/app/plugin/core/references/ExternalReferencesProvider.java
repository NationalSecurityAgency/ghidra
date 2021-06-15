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
package ghidra.app.plugin.core.references;

import java.awt.BorderLayout;
import java.awt.event.MouseEvent;
import java.util.*;

import javax.swing.*;

import org.apache.commons.lang3.StringUtils;

import docking.ActionContext;
import docking.action.builder.ActionBuilder;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.table.AbstractSortedTableModel;
import ghidra.app.cmd.refs.*;
import ghidra.framework.cmd.Command;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTable;
import resources.ResourceManager;

/**
 * ComponentProvider that displays a table of External Programs.
 * <p>
 */
public class ExternalReferencesProvider extends ComponentProviderAdapter {
	private static ImageIcon ADD_ICON = ResourceManager.loadImage("images/Plus.png");
	private static ImageIcon DELETE_ICON = ResourceManager.loadImage("images/edit-delete.png");
	private static ImageIcon EDIT_ICON = ResourceManager.loadImage("images/editbytes.gif");
	private static ImageIcon CLEAR_ICON = ResourceManager.loadImage("images/erase16.png");

	private JPanel mainPanel;
	private ExternalNamesTableModel tableModel;
	private GhidraTable table;
	private Program program;
	private String rowToHighlightDuringNextReload; // hack to reselect a renamed row during the next reload.	

	private DomainObjectListener domainObjectListener = ev -> {
		if (isVisible()) {
			tableModel.updateTableData();
			if (rowToHighlightDuringNextReload != null) {
				int row = tableModel.indexOf(rowToHighlightDuringNextReload);
				rowToHighlightDuringNextReload = null;
				if (row >= 0) {
					table.selectRow(row);
				}
			}
		}
	};

	public ExternalReferencesProvider(ReferencesPlugin plugin) {
		super(plugin.getTool(), "External Programs", plugin.getName());
		mainPanel = buildMainPanel();
		createActions();
		setHelpLocation(new HelpLocation("ReferencesPlugin", "ExternalNamesDialog"));
		addToTool();
	}

	private void createActions() {
		new ActionBuilder("Add External Program Name", getOwner())
				.popupMenuPath("Add External Program")
				.popupMenuIcon(ADD_ICON)
				.toolBarIcon(ADD_ICON)
				.enabledWhen(ac -> program != null)
				.onAction(ac -> addExternalProgram())
				.buildAndInstallLocal(this);

		new ActionBuilder("Delete External Program Name", getOwner())
				.popupMenuPath("Delete External Program")
				.popupMenuIcon(DELETE_ICON)
				.toolBarIcon(DELETE_ICON)
				.enabledWhen(ac -> hasSelectedRows())
				.onAction(ac -> deleteExternalProgram())
				.buildAndInstallLocal(this);

		new ActionBuilder("Set External Name Association", getOwner())
				.popupMenuPath("Set External Name Association")
				.popupMenuIcon(EDIT_ICON)
				.toolBarIcon(EDIT_ICON)
				.enabledWhen(ac -> isSingleRowSelected())
				.onAction(ac -> setExternalProgramAssociation())
				.buildAndInstallLocal(this);

		new ActionBuilder("Clear External Name Association", getOwner())
				.popupMenuPath("Clear External Name Association")
				.popupMenuIcon(CLEAR_ICON)
				.toolBarIcon(CLEAR_ICON)
				.enabledWhen(ac -> hasSelectedRows())
				.onAction(ac -> clearExternalAssociation())
				.buildAndInstallLocal(this);

	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	void setProgram(Program program) {
		rowToHighlightDuringNextReload = null;
		if (this.program != null) {
			this.program.removeListener(domainObjectListener);
		}
		this.program = program;
		if (this.program != null) {
			this.program.addListener(domainObjectListener);
		}

		if (isVisible()) {
			tableModel.updateTableData();
		}
	}

	@Override
	public void componentHidden() {
		tableModel.updateTableData();
	}

	@Override
	public void componentShown() {
		tableModel.updateTableData();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		return new ActionContext(this, table);
	}

	private JPanel buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		tableModel = new ExternalNamesTableModel();
		table = new GhidraTable(tableModel);

		JScrollPane sp = new JScrollPane(table);
		table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
		ToolTipManager.sharedInstance().registerComponent(table);

		panel.add(sp, BorderLayout.CENTER);

		return panel;
	}

	private boolean isSingleRowSelected() {
		return table.getSelectedRowCount() == 1;
	}

	private boolean hasSelectedRows() {
		return table.getSelectedRowCount() > 0;
	}

	public List<String> getSelectedExternalNames() {
		List<String> externalNames = new ArrayList<>();
		for (int rowIndex : table.getSelectedRows()) {
			ExternalNamesRow row = tableModel.getRowObject(rowIndex);
			externalNames.add(row.getName());
		}
		return externalNames;
	}

	void dispose() {
		table.dispose();
	}

	private void addExternalProgram() {
		InputDialog dialog = new InputDialog("New External Program", "Enter Name");
		dialog.setHelpLocation(
			new HelpLocation("ReferencesPlugin", "Add_External_Program_Name"));
		getTool().showDialog(dialog, ExternalReferencesProvider.this);
		if (dialog.isCanceled()) {
			return;
		}
		String newExternalName = dialog.getValue().trim();
		if (newExternalName.isEmpty()) {
			Msg.showError(this, dialog.getComponent(), "Invalid Input",
				"External program name cannot be empty");
			return;
		}
		AddExternalNameCmd cmd =
			new AddExternalNameCmd(newExternalName, SourceType.USER_DEFINED);
		getTool().execute(cmd, program);
	}

	private void deleteExternalProgram() {
		ExternalManager externalManager = program.getExternalManager();
		StringBuilder buf = new StringBuilder();
		CompoundCmd cmd = new CompoundCmd("Delete External Program Name");
		for (String externalName : getSelectedExternalNames()) {
			boolean hasLocations =
				externalManager.getExternalLocations(externalName).hasNext();
			if (hasLocations) {
				buf.append("\n     ");
				buf.append(externalName);
			}
			else {
				cmd.add(new RemoveExternalNameCmd(externalName));
			}
		}
		if (cmd.size() > 0) {
			getTool().execute(cmd, program);
		}
		if (buf.length() > 0) {
			Msg.showError(this, mainPanel, "Delete Failure",
				"The following external reference names could not be deleted\n" +
					"because they contain external locations:\n" + buf.toString());
		}
	}

	private void setExternalProgramAssociation() {
		List<String> selectedExternalNames = getSelectedExternalNames();
		String externalName = selectedExternalNames.get(0);	// must be exactly one for us to be enabled.
		DataTreeDialog dialog = new DataTreeDialog(mainPanel,
			"Choose External Program (" + externalName + ")", DataTreeDialog.OPEN);

		dialog.setSearchText(externalName);

		dialog.addOkActionListener(e1 -> {
			DomainFile domainFile = dialog.getDomainFile();
			if (domainFile == null) {
				return;
			}
			String pathName = domainFile.toString();
			dialog.close();
			ExternalManager externalManager = program.getExternalManager();
			String externalLibraryPath =
				externalManager.getExternalLibraryPath(externalName);
			if (!pathName.equals(externalLibraryPath)) {
				Command cmd =
					new SetExternalNameCmd(externalName, domainFile.getPathname());
				getTool().execute(cmd, program);
			}
		});
		dialog.setHelpLocation(
			new HelpLocation("ReferencesPlugin", "ChooseExternalProgram"));
		getTool().showDialog(dialog);
	}

	private void clearExternalAssociation() {
		CompoundCmd cmd = new CompoundCmd("Clear External Program Associations");
		for (String externalName : getSelectedExternalNames()) {
			cmd.add(new ClearExternalNameCmd(externalName));
		}
		getTool().execute(cmd, program);
	}

	//-----------------------------------------------------------------------------------------
	private static class ExternalNamesRow {

		private String name;
		private String path;

		ExternalNamesRow(String name, String path) {
			this.name = name;
			this.path = path;
		}

		String getName() {
			return name;
		}

		String getPath() {
			return path;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((name == null) ? 0 : name.hashCode());
			result = prime * result + ((path == null) ? 0 : path.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}

			ExternalNamesRow other = (ExternalNamesRow) obj;
			if (!Objects.equals(name, other.name)) {
				return false;
			}
			if (!Objects.equals(path, other.path)) {
				return false;
			}
			return true;
		}

	}

	class ExternalNamesTableModel extends AbstractSortedTableModel<ExternalNamesRow> {

		final static int NAME_COL = 0;
		final static int PATH_COL = 1;
		final static String EXTERNAL_NAME = "Name";
		final static String PATH_NAME = "Ghidra Program";
		private final List<String> columns = List.of(EXTERNAL_NAME, PATH_NAME);

		private List<ExternalNamesRow> paths = new ArrayList<>();

		void updateTableData() {
			paths.clear();

			if (program != null && isVisible()) {
				ExternalManager extMgr = program.getExternalManager();
				String[] programNames = extMgr.getExternalLibraryNames();
				Arrays.sort(programNames);

				for (String programName : programNames) {
					if (Library.UNKNOWN.equals(programName)) {
						continue;
					}

					ExternalNamesRow path =
						new ExternalNamesRow(programName, extMgr.getExternalLibraryPath(programName));
					paths.add(path);
				}
			}
			tableModel.fireTableDataChanged();
		}

		private boolean rowAlreadyExists(String name) {
			return indexOf(name) != -1;
		}

		private int indexOf(String name) {
			for (int i = 0; i < paths.size(); i++) {
				ExternalNamesRow path = paths.get(i);
				if (path.getName().equals(name)) {
					return i;
				}
			}
			return -1;
		}


		@Override
		public void dispose() {
			super.dispose();
			paths.clear();
		}

		@Override
		public int getColumnCount() {
			return columns.size();
		}

		@Override
		public String getColumnName(int column) {
			return columns.get(column);
		}

		@Override
		public String getName() {
			return "External Programs Model";
		}

		@Override
		public boolean isSortable(int columnIndex) {
			return true;
		}

		@Override
		public boolean isCellEditable(int rowIndex, int columnIndex) {
			if (columnIndex == NAME_COL) {
				return true;
			}
			return false;
		}

		@Override
		public List<ExternalNamesRow> getModelData() {
			return paths;
		}

		@Override
		public Object getColumnValueForRow(ExternalNamesRow t, int columnIndex) {

			switch (columnIndex) {
				case NAME_COL:
					return t.getName();
				case PATH_COL:
					return t.getPath();
			}
			return "Unknown Column!";
		}

		@Override
		public void setValueAt(Object aValue, int row, int column) {
			if (column != NAME_COL) {
				return;
			}

			String newName = ((String) aValue).trim();
			ExternalNamesRow path = paths.get(row);
			if (StringUtils.isBlank(newName) || path.getName().equals(newName)) {
				return;
			}

			if (rowAlreadyExists(newName)) {
				Msg.showInfo(getClass(), mainPanel, "Duplicate Name",
					"Name already exists: " + newName);
				return;
			}

			rowToHighlightDuringNextReload = newName;
			String oldName = path.getName();
			Command cmd = new UpdateExternalNameCmd(oldName, newName, SourceType.USER_DEFINED);
			if (!tool.execute(cmd, program)) {
				tool.setStatusInfo(cmd.getStatusMsg());
			}
		}

		@Override
		protected Comparator<ExternalNamesRow> createSortComparator(int columnIndex) {
			if (columnIndex == PATH_COL) {
				// force the path column to have a secondary compare using the name column
				// to ensure a 'stable' sort.  Without this during analysis
				// the constant updates cause the table to sort randomly when
				// there are lots of empty path values. 
				Comparator<ExternalNamesRow> c1 =
					(r1, r2) -> Objects.requireNonNullElse(r1.getPath(), "")
							.compareTo(Objects.requireNonNullElse(r2.getPath(), ""));
				return c1.thenComparing((r1, r2) -> r1.getName().compareTo(r2.getName()));
			}
			return super.createSortComparator(columnIndex);
		}

	}

}
