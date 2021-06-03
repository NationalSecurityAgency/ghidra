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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.swing.*;
import javax.swing.event.TableModelListener;
import javax.swing.table.TableColumn;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.table.*;
import generic.jar.ResourceFile;
import generic.util.Path;
import ghidra.framework.options.SaveState;
import ghidra.framework.preferences.Preferences;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import resources.ResourceManager;

/**
 * Component that has a table to show pathnames; the panel includes buttons to control
 * the order of the paths, and to add and remove paths. The add button brings up a
 * file chooser. Call the setFileChooser() method to control how the file chooser should
 * behave.  If the table entries should not be edited, call setEditingEnabled(false).
 */
public class PathManager {

	private JPanel panel;
	private GTable pathTable;
	private PathManagerModel pathModel;
	private TableModelListener pathModelListener;
	private JButton upButton;
	private JButton downButton;
	private JButton addButton;
	private JButton removeButton;
	private Color selectionColor;
	private GhidraFileChooser fileChooser;
	private String preferenceForLastSelectedDir = Preferences.LAST_IMPORT_DIRECTORY;
	private String title = "Select File";
	private GhidraFileChooserMode fileChooserMode = GhidraFileChooserMode.FILES_ONLY;
	private boolean allowMultiFileSelection;
	private GhidraFileFilter filter;
	private boolean addToTop;
	private boolean allowOrdering;
	private ArrayList<PathManagerListener> listeners = new ArrayList<>();

	/**
	 * Construct a new PathnameTablePanel.
	 * @param paths list of paths to show; may be null
	 * @param addToTop true if new paths are to be added to the top of the table, false
	 * @param allowOrdering if true the ability to move path items up/down will be provided
	 * if new paths are to be added to the end of the table
	 */
	public PathManager(List<Path> paths, boolean addToTop, boolean allowOrdering) {
		this.addToTop = addToTop;
		this.allowOrdering = allowOrdering;
		create(paths);
	}

	public PathManager(boolean addToTop, boolean allowOrdering) {
		this(new ArrayList<>(), addToTop, allowOrdering);
	}

	/**
	 * Set properties on the file chooser that is displayed when the "Add" button is pressed.
	 * @param title title of the file chooser
	 * @param preferenceForLastSelectedDir Preference to use as the current directory in the
	 * file chooser
	 * @param selectionMode mode defined in GhidraFileChooser, e.g., GhidraFileChooser.FILES_ONLY
	 * @param allowMultiSelection true if multiple files can be selected
	 * @param filter filter to use; may be null if no filtering is required
	 */
	public void setFileChooserProperties(String title, String preferenceForLastSelectedDir,
			GhidraFileChooserMode selectionMode, boolean allowMultiSelection,
			GhidraFileFilter filter) {
		this.title = title;
		this.preferenceForLastSelectedDir = preferenceForLastSelectedDir;
		fileChooserMode = selectionMode;
		allowMultiFileSelection = allowMultiSelection;
		this.filter = filter;
		this.fileChooser = null;
	}

	/**
	 * Add a new file path and set its enablement
	 * @param file 
	 * @param enabled
	 * @return true if the enabled path did not already exist
	 */
	public boolean addPath(ResourceFile file, boolean enabled) {
		ResourceFile dir = file.isDirectory() ? file : file.getParentFile();
		for (Path path : pathModel.getAllPaths()) {
			if (path.getPath().equals(dir)) {
				if (enabled && !path.isEnabled()) {
					path.setEnabled(true);
					pathModel.fireTableDataChanged();
					firePathsChanged();
					return true;
				}
				return false;
			}
		}
		Path p = new Path(dir);
		p.setEnabled(enabled);
		pathModel.addPath(p, true);
		Preferences.setProperty(preferenceForLastSelectedDir, dir.getAbsolutePath());
		firePathsChanged();
		return true;
	}

	/**
	 * Set the paths.
	 */
	public void setPaths(List<Path> paths) {
		pathModel.setPaths(paths);
	}

	/**
	 * Clear the paths in the table.
	 */
	public void clear() {
		pathModel.clear();
	}

	public void addListener(PathManagerListener listener) {
		if (!listeners.contains(listener)) {
			listeners.add(listener);
		}
	}

	public void removeListener(PathManagerListener listener) {
		listeners.remove(listener);
	}

	public List<PathManagerListener> getListeners() {
		return new ArrayList<>(listeners);
	}

	private void firePathsChanged() {
		for (PathManagerListener listener : listeners) {
			listener.pathsChanged();
		}
	}

	private void create(List<Path> paths) {
		panel = new JPanel(new BorderLayout(5, 5));

		selectionColor = new Color(204, 204, 255);

		if (allowOrdering) {
			upButton = new JButton(ResourceManager.loadImage("images/up.png"));
			upButton.setName("UpArrow");
			upButton.setToolTipText("Move the selected path up in list");
			upButton.addActionListener(e -> up());
			upButton.setFocusable(false);

			downButton = new JButton(ResourceManager.loadImage("images/down.png"));
			downButton.setName("DownArrow");
			downButton.setToolTipText("Move the selected path down in list");
			downButton.addActionListener(e -> down());
			downButton.setFocusable(false);
		}

		addButton = new JButton(ResourceManager.loadImage("images/Plus.png"));
		addButton.setName("AddPath");
		addButton.setToolTipText("Display file chooser to select files to add");
		addButton.addActionListener(e -> add());
		addButton.setFocusable(false);

		removeButton = new JButton(ResourceManager.loadImage("images/edit-delete.png"));
		removeButton.setName("RemovePath");
		removeButton.setToolTipText("Remove selected path(s) from list");
		removeButton.addActionListener(e -> remove());
		removeButton.setFocusable(false);

		JPanel buttonPanel = new JPanel(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.CENTER;
		gbc.insets = new Insets(0, 0, 0, 0);
		gbc.gridx = 0;
		gbc.gridy = 0;
		if (allowOrdering) {
			buttonPanel.add(upButton, gbc);
			++gbc.gridy;
			buttonPanel.add(downButton, gbc);
			++gbc.gridy;
		}
		buttonPanel.add(addButton, gbc);
		++gbc.gridy;
		buttonPanel.add(removeButton, gbc);

		pathModelListener = e -> firePathsChanged();

		pathModel = new PathManagerModel(this, paths);
		pathModel.addTableModelListener(pathModelListener);

		pathTable = new GTable(pathModel);
		pathTable.setName("PATH_TABLE");
		pathTable.setSelectionBackground(selectionColor);
		pathTable.setSelectionForeground(Color.BLACK);
		pathTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

		//make the 'enabled' column very skinny...
		TableColumn useColumn = pathTable.getColumnModel().getColumn(PathManagerModel.COLUMN_USE);
		int width = 50;
		useColumn.setPreferredWidth(width);
		useColumn.setMinWidth(width);
		useColumn.setMaxWidth(width);
		useColumn.setWidth(width);

		TableColumn pathColumn = pathTable.getColumnModel().getColumn(PathManagerModel.COLUMN_PATH);
		pathColumn.setCellRenderer(new GTableCellRenderer() {
			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {

				JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);

				Object value = data.getValue();
				int column = data.getColumnViewIndex();

				if (column == PathManagerModel.COLUMN_PATH) {
					Path path = (Path) value;
					if (!isValidPath(path)) {
						renderer.setForeground(Color.RED);
					}
				}
				return renderer;
			}
		});

		JScrollPane scrollPane = new JScrollPane(pathTable);
		scrollPane.getViewport().setBackground(pathTable.getBackground());

		ListSelectionModel selModel = pathTable.getSelectionModel();
		selModel.addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			updateButtonsEnabled();
		});
		updateButtonsEnabled();

		panel.add(scrollPane, BorderLayout.CENTER);
		panel.add(buttonPanel, BorderLayout.EAST);
		panel.setPreferredSize(new Dimension(400, 200));
	}

	private void updateButtonsEnabled() {
		int[] rows = pathTable.getSelectedRows();
		if (allowOrdering) {
			if (pathModel.getRowCount() > 1 && rows.length == 1) {
				upButton.setEnabled(true);
				downButton.setEnabled(true);
			}
			else {
				upButton.setEnabled(false);
				downButton.setEnabled(false);
			}
		}
		removeButton.setEnabled(rows.length > 0);
	}

	private void remove() {
		int[] selectedRows = pathTable.getSelectedRows();
		if (selectedRows == null) {
			return;
		}
		pathModel.remove(selectedRows);

		// select the next row based on what was selected
		Arrays.sort(selectedRows);
		int row = selectedRows[selectedRows.length - 1] + 1 - selectedRows.length;
		int count = pathModel.getRowCount();
		if (row >= count) {
			row = count - 1;
		}
		if (row >= 0) {
			pathTable.setRowSelectionInterval(row, row);
		}
		updateButtonsEnabled();
	}

	private void add() {
		if (fileChooser == null) {
			fileChooser = new GhidraFileChooser(panel);
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
					public boolean accept(File f, GhidraFileChooserModel l_model) {
						return filter.accept(f, l_model);
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
		if (!files.isEmpty()) {
			if (allowMultiFileSelection) {
				String parent = files.get(0).getParent();
				Preferences.setProperty(preferenceForLastSelectedDir, parent);
				for (File element : files) {
					Path p = new Path(element.getAbsolutePath());
					pathModel.addPath(p, addToTop);
				}
			}
			else {
				String path = files.get(0).getAbsolutePath();
				Path p = new Path(path);
				pathModel.addPath(p, addToTop);
				Preferences.setProperty(preferenceForLastSelectedDir, path);
			}
		}
	}

	private void up() {
		int row = pathTable.getSelectedRow();
		int newRow = pathModel.moveUp(row);
		pathTable.setRowSelectionInterval(newRow, newRow);
	}

	private void down() {
		int row = pathTable.getSelectedRow();
		int newRow = pathModel.moveDown(row);
		pathTable.setRowSelectionInterval(newRow, newRow);
	}

	/**
	 * Returns the GUI component for the path manager.
	 * @return the GUI component for the path manager
	 */
	public JComponent getComponent() {
		return panel;
	}

	/**
	 * Saves the paths to the specified SaveState object.
	 * @param ss the SaveState object
	 */
	public void saveState(SaveState ss) {
		List<Path> paths = pathModel.getAllPaths();

		String[] pathArr = new String[paths.size()];
		boolean[] enableArr = new boolean[paths.size()];
		boolean[] editArr = new boolean[paths.size()];
		boolean[] readArr = new boolean[paths.size()];

		int index = 0;
		for (Path path : paths) {
			pathArr[index] = path.getPathAsString();
			enableArr[index] = path.isEnabled();
			editArr[index] = path.isEditable();
			readArr[index] = path.isReadOnly();
			++index;
		}

		ss.putStrings("PathManagerPanel_PATH", pathArr);
		ss.putBooleans("PathManagerPanel_ENABLE", enableArr);
		ss.putBooleans("PathManagerPanel_EDIT", editArr);
		ss.putBooleans("PathManagerPanel_READ", readArr);
	}

	/**
	 * Restore paths from user Preferences using the specified keys.  
	 * If preferences have never been saved, the specified {@code defaultEnablePaths}
	 * will be used.  Note: the encoded path list must have been stored
	 * using the same keys using the {@link #savePathsToPreferences(String, String, Path[])}
	 * or {@link #saveToPreferences(String, String)} methods.
	 * @param enablePathKey preference key for storing enabled paths
	 * @param defaultEnablePaths default paths
	 * @param disabledPathKey preference key for storing disabled paths
	 */
	public void restoreFromPreferences(String enablePathKey, Path[] defaultEnablePaths,
			String disabledPathKey) {
		pathModel.clear();
		for (Path path : getPathsFromPreferences(enablePathKey, defaultEnablePaths,
			disabledPathKey)) {
			pathModel.addPath(path, addToTop);
		}
	}

	/**
	 * Restore paths from user Preferences using the specified keys.  
	 * If preferences have never been saved, the specified {@code defaultEnablePaths}
	 * will be returned.  Note: the encoded path list must have been stored
	 * using the same keys using the {@link #savePathsToPreferences(String, String, Path[])}
	 * or {@link #saveToPreferences(String, String)} methods.
	 * @param enablePathKey preference key for storing enabled paths
	 * @param defaultEnablePaths default paths
	 * @param disabledPathKey preference key for storing disabled paths
	 * @return ordered paths from Preferences
	 */
	public static Path[] getPathsFromPreferences(String enablePathKey, Path[] defaultEnablePaths,
			String disabledPathKey) {
		String enablePath = Preferences.getProperty(enablePathKey, null, true);
		if (enablePath != null && enablePath.length() == 0) {
			enablePath = null;
		}
		String disabledPath = Preferences.getProperty(disabledPathKey, null);
		if (disabledPath != null && disabledPath.length() == 0) {
			disabledPath = null;
		}
		String[] enabledPaths = null;
		String[] disabledPaths = null;
		if (defaultEnablePaths != null && enablePath == null && disabledPath == null) {
			return defaultEnablePaths;
		}

		enabledPaths = enablePath != null ? enablePath.split(File.pathSeparator) : new String[0];

		disabledPaths =
			disabledPath != null ? disabledPath.split(File.pathSeparator) : new String[0];

		ArrayList<Path> list = new ArrayList<>();
		int disabledIndex = 0;
		for (String p : enabledPaths) {
			if (p.length() == 0) {
				// insert next disabled path at empty placeholder
				if (disabledIndex < disabledPaths.length) {
					list.add(new Path(disabledPaths[disabledIndex++], false));
				}
			}
			else {
				list.add(new Path(p, true));
			}
		}
		// add remaining disabled paths
		for (int i = disabledIndex; i < disabledPaths.length; i++) {
			list.add(new Path(disabledPaths[i], false));
		}
		Path[] paths = new Path[list.size()];
		return list.toArray(paths);
	}

	public boolean saveToPreferences(String enablePathKey, String disabledPathKey) {
		List<Path> pathList = pathModel.getAllPaths();
		return savePathsToPreferences(enablePathKey, disabledPathKey,
			pathList.toArray(new Path[pathList.size()]));
	}

	private static void appendPath(StringBuilder buf, String path, boolean previousPathIsEmpty) {
		if (buf.length() != 0 || previousPathIsEmpty) {
			buf.append(File.pathSeparatorChar);
		}
		buf.append(path);
	}

	/**
	 * Save the specified paths to the user Preferences using the specified keys.
	 * Note: The encoded path Preferences are intended to be decoded by the 
	 * {@link #restoreFromPreferences(String, Path[], String)} and
	 * {@link #getPathsFromPreferences(String, Path[], String)} methods.
	 * @param enablePathKey preference key for storing enabled paths
	 * @param disabledPathKey preference key for storing disabled paths
	 * @param paths paths to be saved
	 * @return true if Preference saved properly
	 */
	public static boolean savePathsToPreferences(String enablePathKey, String disabledPathKey,
			Path[] paths) {
		StringBuilder enabledPathBuffer = new StringBuilder();
		StringBuilder disabledPathBuffer = new StringBuilder();
		boolean previousPathDisabled = false;
		for (Path path : paths) {
			if (path.isEnabled()) {
				appendPath(enabledPathBuffer, path.getPathAsString(), previousPathDisabled);
				previousPathDisabled = false;
			}
			else {
				appendPath(disabledPathBuffer, path.getPathAsString(), false);
				appendPath(enabledPathBuffer, "", previousPathDisabled);
				previousPathDisabled = true;
			}
		}
		if (enablePathKey != null) {
			Preferences.setProperty(enablePathKey, enabledPathBuffer.toString());
		}
		if (disabledPathKey != null) {
			Preferences.setProperty(disabledPathKey, disabledPathBuffer.toString());
		}
		return Preferences.store();
	}

	/**
	 * Restores the paths from the specified SaveState object.
	 * @param ss the SaveState object
	 */
	public void restoreState(SaveState ss) {
		String[] pathArr = ss.getStrings("PathManagerPanel_PATH", new String[0]);

		if (pathArr.length == 0) {
			return;
		}

		/*
		 * Temporarily remove the listener to prevent too many
		 * notifications from being sent.
		 */
		pathModel.removeTableModelListener(pathModelListener);

		boolean[] enableArr =
			ss.getBooleans("PathManagerPanel_ENABLE", new boolean[pathArr.length]);
		boolean[] editArr = ss.getBooleans("PathManagerPanel_EDIT", new boolean[pathArr.length]);
		boolean[] readArr = ss.getBooleans("PathManagerPanel_READ", new boolean[pathArr.length]);

		List<Path> oldPaths = pathModel.getAllPaths();
		pathModel.clear();

		for (int i = 0; i < pathArr.length; i++) {
			Path path = new Path(pathArr[i], enableArr[i], editArr[i], readArr[i]);
			Path oldPath = getPath(path.getPathAsString(), oldPaths);
			if (oldPath != null) {
				if (!oldPath.isEditable()) {
					boolean enabled = path.isEnabled();
					path = oldPath;
					path.setEnabled(enabled);
				}
				oldPaths.remove(oldPath);
			}
			else if (path.isReadOnly()) {
				// skip read-only paths which are not present in the current config
				// This is needed to thin-out old default entries
				continue;
			}
			pathModel.addPath(path, false);
		}

		for (Path path : oldPaths) {
			if (!path.isEditable()) {
				pathModel.addPath(path, false);
			}
		}

		/*
		 * Reinstall the listener then fire the update.
		 */
		pathModel.addTableModelListener(pathModelListener);
		firePathsChanged();
	}

	private static Path getPath(String filepath, List<Path> paths) {
		for (Path path : paths) {
			if (filepath.equals(path.getPathAsString())) {
				return path;
			}
		}
		return null;
	}

	private boolean isValidPath(Path path) {
		if (fileChooserMode == GhidraFileChooserMode.FILES_ONLY && path.getPath().isDirectory()) {
			return false;
		}
		if (fileChooserMode == GhidraFileChooserMode.DIRECTORIES_ONLY && path.getPath().isFile()) {
			return false;
		}
		return path.exists();
	}

	public void dispose() {
		pathTable.dispose();
	}
}
