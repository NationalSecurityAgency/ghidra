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
package docking.widgets.pathmanager;

import java.awt.*;
import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import javax.swing.*;

import docking.widgets.OptionDialog;
import docking.widgets.button.GButton;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.table.*;
import generic.theme.GIcon;
import ghidra.framework.preferences.Preferences;
import ghidra.util.filechooser.GhidraFileFilter;
import resources.Icons;
import utility.function.Callback;

/**
 * Component that has a table to show pathnames; the panel includes buttons to control the order of
 * the paths, and to add and remove paths. The add button brings up a file chooser. Call the
 * setFileChooser() method to control how the file chooser should behave. If the table entries
 * should not be edited, call setEditingEnabled(false).
 */
public class PathnameTablePanel extends JPanel {

	private static final Icon RESET_ICON = new GIcon("icon.widget.pathmanager.reset");

	private JTable pathnameTable;
	private PathnameTableModel tableModel;
	private JButton upButton;
	private JButton downButton;
	private JButton addButton;
	private JButton removeButton;
	private JButton resetButton;
	private String preferenceForLastSelectedDir = Preferences.LAST_PATH_DIRECTORY;
	private String title = "Select File";
	private boolean allowMultiFileSelection;
	private GhidraFileFilter filter;
	private boolean addToTop;
	private boolean ordered;

	private Callback resetCallback;

	private GhidraFileChooserMode fileChooserMode = GhidraFileChooserMode.FILES_ONLY;

	/**
	 * Construct a new PathnameTablePanel.
	 * 
	 * @param paths list of paths to show; may be null
	 * @param enableEdits true to allow editing of entries <em>directly in the table</em>, i.e., via
	 *            the cell editor. The add and remove buttons still allow modification of the list.
	 * @param addToTop true if the add button should add entries to the top of the list. False to
	 *            add entries to the bottom. This behavior is overridden if if {@code ordered} is
	 *            false.
	 * @param ordered true if the order of entries matters. If so, up and down buttons are provided
	 *            so the user may arrange the entries. If not, entries are sorted alphabetically.
	 */
	public PathnameTablePanel(String[] paths, boolean enableEdits, boolean addToTop,
			boolean ordered) {
		super(new BorderLayout(5, 5));
		this.addToTop = addToTop;
		this.ordered = ordered;
		tableModel = new PathnameTableModel(paths, enableEdits);
		create();
	}

	/**
	 * Construct a new PathnameTablePanel with a reset button
	 * 
	 * @param paths list of paths to show; may be null
	 * @param resetCallback callback containing the action to perform if the reset button is pressed
	 * @param enableEdits true to allow editing of entries <em>directly in the table</em>, i.e., via
	 *            the cell editor. The add and remove buttons still allow modification of the list.
	 * @param addToTop true if the add button should add entries to the top of the list. False to
	 *            add entries to the bottom. This behavior is overridden if if {@code ordered} is
	 *            false.
	 * @param ordered true if the order of entries matters. If so, up and down buttons are provided
	 *            so the user may arrange the entries. If not, entries are sorted alphabetically.
	 */
	public PathnameTablePanel(String[] paths, Callback resetCallback, boolean enableEdits,
			boolean addToTop, boolean ordered) {
		super(new BorderLayout(5, 5));
		this.addToTop = addToTop;
		this.ordered = ordered;
		this.resetCallback = resetCallback;
		tableModel = new PathnameTableModel(paths, enableEdits);
		create();
	}

	/**
	 * Set properties on the file chooser that is displayed when the "Add" button is pressed.
	 * 
	 * @param title title of the file chooser
	 * @param preferenceForLastSelectedDir Preference to use as the current directory in the file
	 *            chooser
	 * @param selectionMode mode defined in GhidraFileFilter, e.g., GhidraFileFilter.FILES_ONLY
	 * @param allowMultiSelection true if multiple files can be selected
	 * @param filter filter to use; may be null if no filtering is required
	 */
	public void setFileChooserProperties(String title, String preferenceForLastSelectedDir,
			GhidraFileChooserMode selectionMode, boolean allowMultiSelection,
			GhidraFileFilter filter) {

		this.title = Objects.requireNonNull(title);
		this.preferenceForLastSelectedDir = preferenceForLastSelectedDir;
		this.fileChooserMode = Objects.requireNonNull(selectionMode);
		this.allowMultiFileSelection = allowMultiSelection;
		this.filter = filter;
	}

	/**
	 * Set whether the entries in the table can be edited.
	 * 
	 * @param enableEdits false means to not allow editing; the table is editable by default.
	 */
	public void setEditingEnabled(boolean enableEdits) {
		tableModel.setEditingEnabled(enableEdits);
	}

	/**
	 * Set whether new paths should be added to the top of the table (true) or at the end of the
	 * table (false).
	 * 
	 * @param addToTop true means to add to the top of the table
	 */
	public void setAddToTop(boolean addToTop) {
		this.addToTop = addToTop;
	}

	/**
	 * Set whether the order of entries in the table matters.
	 * 
	 * <p>
	 * <b>WARNING:</b> When this is set to false, the entries are immediately sorted and the up and
	 * down buttons removed. Setting it back to true will replace the buttons, but will <em>not</em>
	 * restore the order. In general, this should be set once, at the start of the table's life
	 * cycle.
	 * 
	 * @param ordered true means the user can control the order, false means they cannot.
	 */
	public void setOrdered(boolean ordered) {
		this.ordered = ordered;
		upButton.setVisible(ordered);
		downButton.setVisible(ordered);
		if (!ordered) {
			tableModel.sortPaths();
		}
	}

	public String[] getPaths() {
		String[] paths = new String[tableModel.getRowCount()];
		for (int i = 0; i < paths.length; i++) {
			paths[i] = (String) tableModel.getValueAt(i, 0);
		}
		return paths;
	}

	public void setPaths(String[] paths) {
		tableModel.setPaths(paths, !ordered);
	}

	public JTable getTable() {
		return pathnameTable;
	}

	/**
	 * Clear the paths in the table.
	 *
	 */
	public void clear() {
		setPaths(new String[0]);
	}

	private void create() {

		upButton = new GButton(Icons.UP_ICON);
		upButton.setName("UpArrow");
		upButton.setToolTipText("Move the selected path up in list");
		upButton.addActionListener(e -> up());
		upButton.setVisible(ordered);
		downButton = new GButton(Icons.DOWN_ICON);
		downButton.setName("DownArrow");
		downButton.setToolTipText("Move the selected path down in list");
		downButton.addActionListener(e -> down());
		downButton.setVisible(ordered);
		addButton = new GButton(Icons.ADD_ICON);
		addButton.setName("AddPath");
		addButton.setToolTipText("Display file chooser to select paths to add");
		addButton.addActionListener(e -> add());
		removeButton = new GButton(Icons.DELETE_ICON);
		removeButton.setName("RemovePath");
		removeButton.setToolTipText("Remove selected path(s) from list");
		removeButton.addActionListener(e -> remove());

		resetButton = new GButton(RESET_ICON);
		resetButton.setName("RefreshPaths");
		resetButton.setToolTipText("Resets path list to the default values");
		resetButton.addActionListener(e -> reset());

		Box buttonBox = Box.createVerticalBox();
		buttonBox.add(upButton);
		buttonBox.add(downButton);
		buttonBox.add(addButton);
		buttonBox.add(removeButton);
		if (resetCallback != null) {
			buttonBox.add(resetButton);
		}

		pathnameTable = new GTable(tableModel);
		pathnameTable.setShowGrid(false);

		pathnameTable.setPreferredScrollableViewportSize(new Dimension(330, 200));
		pathnameTable.setTableHeader(null);
		pathnameTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		JScrollPane scrollPane = new JScrollPane(pathnameTable);
		scrollPane.getViewport().setBackground(pathnameTable.getBackground());

		setDefaultCellRenderer();

		add(scrollPane, BorderLayout.CENTER);
		add(buttonBox, BorderLayout.EAST);

		ListSelectionModel selModel = pathnameTable.getSelectionModel();
		selModel.addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			updateButtonsEnabled();
		});
		updateButtonsEnabled();
	}

	private void updateButtonsEnabled() {
		int[] rows = pathnameTable.getSelectedRows();
		if (tableModel.getRowCount() > 1 && rows.length == 1) {
			upButton.setEnabled(true);
			downButton.setEnabled(true);
		}
		else {
			upButton.setEnabled(false);
			downButton.setEnabled(false);
		}
		removeButton.setEnabled(rows.length > 0);
	}

	private void setDefaultCellRenderer() {

		pathnameTable.setDefaultRenderer(String.class, new GTableCellRenderer() {

			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {

				JLabel label = (JLabel) super.getTableCellRendererComponent(data);
				Object value = data.getValue();

				String pathName = (String) value;

				boolean fileExists = true;
				if (pathName == null) {
					pathName = "";
				}
				else {
					File file = new File(pathName);
					fileExists = file.exists();
				}

				label.setText(pathName.toString());
				if (!fileExists) {
					label.setForeground(getErrorForegroundColor(data.isSelected()));
				}

				return label;
			}
		});
	}

	private void remove() {
		int[] selectedRows = pathnameTable.getSelectedRows();
		if (selectedRows == null) {
			return;
		}
		tableModel.remove(selectedRows);

		// select the next row based on what was selected
		Arrays.sort(selectedRows);
		int row = selectedRows[selectedRows.length - 1] + 1 - selectedRows.length;
		int count = tableModel.getRowCount();
		if (row >= count) {
			row = count - 1;
		}
		if (row >= 0) {
			pathnameTable.setRowSelectionInterval(row, row);
		}
		updateButtonsEnabled();
	}

	private void add() {

		GhidraFileChooser fileChooser = new GhidraFileChooser(this);
		fileChooser.setMultiSelectionEnabled(allowMultiFileSelection);
		fileChooser.setFileSelectionMode(fileChooserMode);
		fileChooser.setTitle(title);
		fileChooser.setApproveButtonToolTipText(title);
		if (filter != null) {
			fileChooser.addFileFilter(filter);
		}
		String dir = Preferences.getProperty(preferenceForLastSelectedDir);
		if (dir != null) {
			fileChooser.setCurrentDirectory(new File(dir));
		}

		List<File> files = fileChooser.getSelectedFiles();
		String[] paths = files.stream().map(File::getAbsolutePath).toArray(String[]::new);
		if (!files.isEmpty()) {
			if (allowMultiFileSelection) {
				String parent = files.get(0).getParent();
				Preferences.setProperty(preferenceForLastSelectedDir, parent);
			}
			else {
				Preferences.setProperty(preferenceForLastSelectedDir, paths[0]);
			}
		}

		fileChooser.dispose();

		tableModel.addPaths(paths, addToTop, !ordered);
	}

	private void up() {
		int row = pathnameTable.getSelectedRow();
		tableModel.moveUp(pathnameTable, row);
	}

	private void down() {
		int row = pathnameTable.getSelectedRow();
		tableModel.moveDown(pathnameTable, row);
	}

	protected int promptConfirmReset() {
		String confirmation = """
				<html><body width="200px">
				  Are you sure you would like to reset the paths to the default list?
				  This will remove all paths manually added.
				</html>""";
		String header = "Reset Paths?";

		return OptionDialog.showYesNoDialog(this, header, confirmation);
	}

	private void reset() {
		int optionChosen = promptConfirmReset();
		if (resetCallback != null && optionChosen == OptionDialog.YES_OPTION) {
			resetCallback.call();
		}
	}
}
