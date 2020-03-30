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
package ghidra.app.plugin.core.script.osgi;

import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.table.TableColumn;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.table.*;
import generic.jar.ResourceFile;
import ghidra.app.script.osgi.BundleHost;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import resources.ResourceManager;

/**
 * component for managing OSGi bundle status
 */
public class BundleStatusProvider extends ComponentProviderAdapter {
	static String preferenceForLastSelectedBundle = "LastGhidraScriptBundle";

	private JPanel panel;
	private GTable bundlePathTable;
	private final BundleStatusModel bundleStatusModel;
	private JButton addButton;
	private JButton removeButton;
	private Color selectionColor;
	private GhidraFileChooser fileChooser;
	private GhidraFileFilter filter;
	private ArrayList<BundlePathManagerListener> listeners = new ArrayList<>();

	public void notifyTableChanged() {
		bundlePathTable.notifyTableChanged(new TableModelEvent(bundleStatusModel));
	}

	void fireBundlesChanged() {
		for (BundlePathManagerListener listener : listeners) {
			listener.bundlesChanged();
		}
	}

	void fireBundleEnablementChanged(BundlePath path, boolean newValue) {
		for (BundlePathManagerListener listener : listeners) {
			listener.bundleEnablementChanged(path, newValue);
		}
	}

	void fireBundleActivationChanged(BundlePath path, boolean newValue) {
		for (BundlePathManagerListener listener : listeners) {
			listener.bundleActivationChanged(path, newValue);
		}
	}

	public BundleStatusProvider(PluginTool tool, String owner, BundleHost bundleHost) {
		super(tool, "Bundle Status Manager", owner);
		this.bundleStatusModel = new BundleStatusModel(this, bundleHost);

		this.filter = new GhidraFileFilter() {
			@Override
			public String getDescription() {
				return "Source code directory, bundle (*.jar), or bnd script (*.bnd)";
			}

			@Override
			public boolean accept(File path, GhidraFileChooserModel model) {
				return BundlePath.getType(path) != BundlePath.Type.INVALID;
			}
		};
		this.fileChooser = null;

		build();
		addToTool();
	}

	public BundleStatusModel getModel() {
		return bundleStatusModel;
	}

	public void addListener(BundlePathManagerListener listener) {
		if (!listeners.contains(listener)) {
			listeners.add(listener);
		}
	}

	public void removeListener(BundlePathManagerListener listener) {
		listeners.remove(listener);
	}

	private void build() {
		panel = new JPanel(new BorderLayout(5, 5));

		selectionColor = new Color(204, 204, 255);

		addButton = new JButton(ResourceManager.loadImage("images/Plus.png"));
		addButton.setName("AddBundle");
		addButton.setToolTipText("Display file chooser to add bundles to list");
		addButton.addActionListener(e -> addButtonAction());
		addButton.setFocusable(false);

		removeButton = new JButton(ResourceManager.loadImage("images/edit-delete.png"));
		removeButton.setName("RemoveBundle");
		removeButton.setToolTipText("Remove selected bundle(s) from list");
		removeButton.addActionListener(e -> removeButtonAction());
		removeButton.setFocusable(false);

		JPanel buttonPanel = new JPanel(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.CENTER;
		gbc.insets = new Insets(0, 0, 0, 0);
		gbc.gridx = 0;
		gbc.gridy = 0;

		buttonPanel.add(addButton, gbc);
		++gbc.gridy;
		buttonPanel.add(removeButton, gbc);

		bundlePathTable = new GTable(bundleStatusModel);
		bundlePathTable.setName("BUNDLEPATH_TABLE");
		bundlePathTable.setSelectionBackground(selectionColor);
		bundlePathTable.setSelectionForeground(Color.BLACK);
		bundlePathTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

		// to allow custom cell renderers
		bundlePathTable.setAutoCreateColumnsFromModel(false);

		int skinnyWidth = 50;

		TableColumn column =
			bundlePathTable.getColumnModel().getColumn(bundleStatusModel.enabledColumn.index);
		column.setPreferredWidth(skinnyWidth);
		column.setMinWidth(skinnyWidth);
		column.setMaxWidth(skinnyWidth);
		column.setWidth(skinnyWidth);

		column = bundlePathTable.getColumnModel().getColumn(bundleStatusModel.activeColumn.index);
		column.setPreferredWidth(skinnyWidth);
		column.setMinWidth(skinnyWidth);
		column.setMaxWidth(skinnyWidth);
		column.setWidth(skinnyWidth);
		column.setCellRenderer(new GBooleanCellRenderer() {
			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {
				BundlePath path = (BundlePath) data.getRowObject();
				Component x = super.getTableCellRendererComponent(data);
				if (path.getBusy()) {
					cb.setVisible(false);
					cb.setEnabled(false);
					setHorizontalAlignment(SwingConstants.CENTER);
					setText("...");
				}
				else {
					cb.setVisible(true);
					cb.setEnabled(true);
					setText("");
				}
				return x;

			}

		});

		column = bundlePathTable.getColumnModel().getColumn(bundleStatusModel.typeColumn.index);

		FontMetrics fontmetrics = panel.getFontMetrics(panel.getFont());
		column.setMaxWidth(10 +
			SwingUtilities.computeStringWidth(fontmetrics, BundlePath.Type.SourceDir.toString()));

		column = bundlePathTable.getColumnModel().getColumn(bundleStatusModel.pathColumn.index);
		column.setCellRenderer(new GTableCellRenderer() {
			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {
				JLabel c = (JLabel) super.getTableCellRendererComponent(data);

				BundlePath path = (BundlePath) data.getValue();
				if (!path.exists()) {
					c.setForeground(Color.RED);
				}
				return c;
			}
		});

		GTableFilterPanel<BundlePath> filterPanel =
			new GTableFilterPanel<>(bundlePathTable, bundleStatusModel);

		JScrollPane scrollPane = new JScrollPane(bundlePathTable);
		scrollPane.getViewport().setBackground(bundlePathTable.getBackground());

		ListSelectionModel selModel = bundlePathTable.getSelectionModel();
		selModel.addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			updateButtonsEnabled();
		});
		updateButtonsEnabled();

		JPanel centerPanel = new JPanel(new BorderLayout());
		centerPanel.add(scrollPane, BorderLayout.CENTER);
		centerPanel.add(filterPanel, BorderLayout.SOUTH);
		panel.add(centerPanel, BorderLayout.CENTER);
		panel.add(buttonPanel, BorderLayout.EAST);
		panel.setPreferredSize(new Dimension(800, 400));
	}

	private void updateButtonsEnabled() {
		int[] rows = bundlePathTable.getSelectedRows();
		removeButton.setEnabled(rows.length > 0);
	}

	private void removeButtonAction() {
		int[] selectedRows = bundlePathTable.getSelectedRows();
		if (selectedRows == null || selectedRows.length == 0) {
			return;
		}
		bundleStatusModel.remove(selectedRows);

		// select the next row based on what was selected
		Arrays.sort(selectedRows);
		int row = selectedRows[selectedRows.length - 1] + 1 - selectedRows.length;
		int count = bundleStatusModel.getRowCount();
		if (row >= count) {
			row = count - 1;
		}
		if (row >= 0) {
			bundlePathTable.setRowSelectionInterval(row, row);
		}
		updateButtonsEnabled();
		fireBundlesChanged();
	}

	private void addButtonAction() {
		if (fileChooser == null) {
			fileChooser = new GhidraFileChooser(panel);
			fileChooser.setMultiSelectionEnabled(true);
			fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_AND_DIRECTORIES);
			fileChooser.setTitle("Select Script Bundle(s)");
			// fileChooser.setApproveButtonToolTipText(title);
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
			String lastSelected = Preferences.getProperty(preferenceForLastSelectedBundle);
			if (lastSelected != null) {
				File f = new File(lastSelected);
				fileChooser.setSelectedFile(f);
			}
		}
		else {
			String lastSelected = Preferences.getProperty(preferenceForLastSelectedBundle);
			if (lastSelected != null) {
				File f = new File(lastSelected);
				fileChooser.setSelectedFile(f);
			}
			fileChooser.rescanCurrentDirectory();
		}

		List<File> files = fileChooser.getSelectedFiles();
		if (!files.isEmpty()) {
			Preferences.setProperty(preferenceForLastSelectedBundle,
				files.get(0).getAbsolutePath());
			for (File element : files) {
				bundleStatusModel.addNewPath(new ResourceFile(element), true, false);
			}
			fireBundlesChanged();
		}
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	/**
	 * Saves the paths to the specified SaveState object.
	 * @param ss the SaveState object
	 */
	public void saveState(SaveState ss) {
		List<BundlePath> paths = bundleStatusModel.getAllPaths();

		String[] pathArr = new String[paths.size()];
		boolean[] enableArr = new boolean[paths.size()];
		boolean[] readonlyArr = new boolean[paths.size()];

		int index = 0;
		for (BundlePath path : paths) {
			pathArr[index] = path.getPathAsString();
			enableArr[index] = path.isEnabled();
			readonlyArr[index] = path.isReadOnly();
			++index;
		}

		ss.putStrings("BundleStatus_PATH", pathArr);
		ss.putBooleans("BundleStatus_ENABLE", enableArr);
		ss.putBooleans("BundleStatus_READ", readonlyArr);
	}

	/**
	 * Restores the paths from the specified SaveState object.
	 * @param ss the SaveState object
	 */
	public void restoreState(SaveState ss) {
		String[] pathArr = ss.getStrings("BundleStatus_PATH", new String[0]);

		if (pathArr.length == 0) {
			return;
		}

		boolean[] enableArr = ss.getBooleans("BundleStatus_ENABLE", new boolean[pathArr.length]);
		boolean[] readonlyArr = ss.getBooleans("BundleStatus_READ", new boolean[pathArr.length]);

		List<BundlePath> currentPaths = bundleStatusModel.getAllPaths();
		bundleStatusModel.clear();

		for (int i = 0; i < pathArr.length; i++) {
			BundlePath currentPath = getPath(pathArr[i], currentPaths);
			if (currentPath != null) {
				currentPaths.remove(currentPath);
				bundleStatusModel.addNewPath(pathArr[i],enableArr[i],readonlyArr[i]);
			}
			else if (!readonlyArr[i]) {
				// skip read-only paths which are not present in the current config
				// This is needed to thin-out old default entries
				bundleStatusModel.addNewPath(pathArr[i],enableArr[i],readonlyArr[i]);
			}
		}
		fireBundlesChanged();
	}

	private static BundlePath getPath(String filepath, List<BundlePath> paths) {
		for (BundlePath path : paths) {
			if (filepath.equals(path.getPathAsString())) {
				return path;
			}
		}
		return null;
	}

	public void dispose() {
		bundlePathTable.dispose();
	}

}
