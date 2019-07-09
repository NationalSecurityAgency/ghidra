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
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.table.*;
import ghidra.framework.preferences.Preferences;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import resources.ResourceManager;
import utility.function.Callback;

/**
 * Component that has a table to show pathnames; the panel includes buttons to control
 * the order of the paths, and to add and remove paths. The add button brings up a
 * file chooser. Call the setFileChooser() method to control how the file chooser should
 * behave.  If the table entries should not be edited, call setEditingEnabled(false).
 *
 *
 *
 */
public class PathnameTablePanel extends JPanel {
	private static final long serialVersionUID = 1L;

	private static final Icon RESET_ICON = ResourceManager.loadImage("images/trash-empty.png");

	private JTable pathnameTable;
	private PathnameTableModel tableModel;
	private JButton upButton;
	private JButton downButton;
	private JButton addButton;
	private JButton removeButton;
	private JButton resetButton;
	private Color selectionColor;
	private GhidraFileChooser fileChooser;
	private String preferenceForLastSelectedDir = Preferences.LAST_IMPORT_DIRECTORY;
	private String title = "Select File";
	private boolean allowMultiFileSelection;
	private GhidraFileFilter filter;
	private boolean addToTop;

	private Callback resetCallback;

	private GhidraFileChooserMode fileChooserMode = GhidraFileChooserMode.FILES_ONLY;

	/**
	 * Construct a new PathnameTablePanel.
	 * @param paths list of paths to show; may be null
	 * @param enableEdits true if edits should be allowed
	 * @param addToTop true if new paths are to be added to the top of the table, false
	 * if new paths are to be added to the end of the table
	 */
	public PathnameTablePanel(String[] paths, boolean enableEdits, boolean addToTop) {
		super(new BorderLayout(5, 5));
		this.addToTop = addToTop;
		tableModel = new PathnameTableModel(paths, enableEdits);
		create();
	}

	/**
	 * Construct a new PathnameTablePanel will a reset button
	 * @param paths list of paths to show; may be null
	 * @param enableEdits true if edits should be allowed
	 * @param addToTop true if new paths are to be added to the top of the table, false
	 * @param resetCallback Callback containing the action to perform if the reset button is pressed
	 * if new paths are to be added to the end of the table
	 */
	public PathnameTablePanel(String[] paths, boolean enableEdits, boolean addToTop,
			Callback resetCallback) {
		super(new BorderLayout(5, 5));
		this.addToTop = addToTop;
		this.resetCallback = resetCallback;
		tableModel = new PathnameTableModel(paths, enableEdits);
		create();
	}

	/**
	 * Set properties on the file chooser that is displayed when the "Add" button is pressed.
	 * @param title title of the file chooser
	 * @param preferenceForLastSelectedDir Preference to use as the current directory in the
	 * file chooser
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
	 * @param enableEdits false means to not allow editing; the table is editable by default.
	 */
	public void setEditingEnabled(boolean enableEdits) {
		tableModel.setEditingEnabled(enableEdits);
	}

	/**
	 * Set whether new paths should be added to the top of the table (true) or at the end of
	 * the table (false).
	 * @param addToTop true means to add to the top of the table
	 */
	public void setAddToTop(boolean addToTop) {
		this.addToTop = addToTop;
	}

	/**
	 * Return paths in the table.
	 */
	public String[] getPaths() {
		String[] paths = new String[tableModel.getRowCount()];
		for (int i = 0; i < paths.length; i++) {
			paths[i] = (String) tableModel.getValueAt(i, 0);
		}
		return paths;
	}

	/**
	 * Set the paths.
	 */
	public void setPaths(String[] paths) {
		tableModel.setPaths(paths);
	}

	/**
	 * Get the table in this path name panel.
	 */
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
		selectionColor = new Color(204, 204, 255);

		upButton = new JButton(ResourceManager.loadImage("images/up.png"));
		upButton.setName("UpArrow");
		upButton.setToolTipText("Move the selected path up in list");
		upButton.addActionListener(e -> up());
		downButton = new JButton(ResourceManager.loadImage("images/down.png"));
		downButton.setName("DownArrow");
		downButton.setToolTipText("Move the selected path down in list");
		downButton.addActionListener(e -> down());
		addButton = new JButton(ResourceManager.loadImage("images/Plus.png"));
		addButton.setName("AddPath");
		addButton.setToolTipText("Display file chooser to select files to add");
		addButton.addActionListener(e -> add());
		removeButton = new JButton(ResourceManager.loadImage("images/edit-delete.png"));
		removeButton.setName("RemovePath");
		removeButton.setToolTipText("Remove selected path(s) from list");
		removeButton.addActionListener(e -> remove());

		resetButton = new JButton(RESET_ICON);
		resetButton.setName("RefreshPaths");
		resetButton.setToolTipText("Resets path list to the default values");
		resetButton.addActionListener(e -> reset());

		JPanel buttonPanel = new JPanel(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.NORTH;
		gbc.insets = new Insets(0, 0, 0, 0);
		gbc.gridx = 0;
		gbc.gridy = 0;
		buttonPanel.add(upButton, gbc);
		gbc.gridy = 1;
		buttonPanel.add(downButton, gbc);
		gbc.gridy = 2;
		buttonPanel.add(addButton, gbc);

		if (resetCallback != null) {
			gbc.gridy = 3;
			buttonPanel.add(removeButton, gbc);

			gbc.weighty = 1;
			gbc.gridy = 4;
			buttonPanel.add(resetButton, gbc);
		}
		else {
			gbc.weighty = 1;
			gbc.gridy = 3;
			buttonPanel.add(removeButton, gbc);
		}

		pathnameTable = new GTable(tableModel);
		pathnameTable.setShowGrid(false);

		pathnameTable.setPreferredScrollableViewportSize(new Dimension(330, 200));
		pathnameTable.setSelectionBackground(selectionColor);
		pathnameTable.setSelectionForeground(Color.BLACK);
		pathnameTable.setTableHeader(null);
		pathnameTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		JScrollPane scrollPane = new JScrollPane(pathnameTable);
		scrollPane.getViewport().setBackground(pathnameTable.getBackground());

		setDefaultCellRenderer();

		add(scrollPane, BorderLayout.CENTER);
		add(buttonPanel, BorderLayout.EAST);

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

				JTable table = data.getTable();
				Object value = data.getValue();
				boolean isSelected = data.isSelected();

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
				Color fg = isSelected ? table.getSelectionForeground() : table.getForeground();
				label.setForeground(!fileExists ? Color.RED : fg);

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
		if (fileChooser == null) {
			fileChooser = new GhidraFileChooser(this);
			fileChooser.setMultiSelectionEnabled(allowMultiFileSelection);
			fileChooser.setFileSelectionMode(fileChooserMode);
			fileChooser.setTitle(title);
			fileChooser.setApproveButtonToolTipText(title);
			if (filter != null) {
				fileChooser.addFileFilter(new GhidraFileFilter() {
					@Override
					public String getDescription() {
						return filter.getDescription();
					}

					@Override
					public boolean accept(File f, GhidraFileChooserModel model) {
						return filter.accept(f, model);
					}
				});
			}
			String dir = Preferences.getProperty(preferenceForLastSelectedDir);
			if (dir != null) {
				fileChooser.setCurrentDirectory(new File(dir));
			}
		}
		else {
			fileChooser.rescanCurrentDirectory();
		}

		List<File> files = fileChooser.getSelectedFiles();
		String[] paths = new String[0];
		if (!files.isEmpty()) {
			if (allowMultiFileSelection) {
				String parent = files.get(0).getParent();
				Preferences.setProperty(preferenceForLastSelectedDir, parent);
				paths = new String[files.size()];
				for (int i = 0; i < files.size(); i++) {
					paths[i] = files.get(i).getAbsolutePath();
				}
			}
			else {
				paths = new String[1];
				paths[0] = files.get(0).getAbsolutePath();
				Preferences.setProperty(preferenceForLastSelectedDir, paths[0]);
			}
		}

		tableModel.addPaths(paths, addToTop);
	}

	private void up() {
		int row = pathnameTable.getSelectedRow();
		tableModel.moveUp(pathnameTable, row);
	}

	private void down() {
		int row = pathnameTable.getSelectedRow();
		tableModel.moveDown(pathnameTable, row);
	}

	private void reset() {
		String confirmation = "Are you sure you would like to reset\nlibrary" +
			" paths to the default list? This\nwill remove all paths manually added.";
		String header = "Reset Library Paths?";

		int optionChosen = OptionDialog.showYesNoDialog(this, header, confirmation);

		if (resetCallback != null && optionChosen == OptionDialog.YES_OPTION) {
			resetCallback.call();
		}
	}
}
