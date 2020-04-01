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
import java.util.Arrays;
import java.util.List;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.table.TableColumn;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.table.*;
import ghidra.app.script.osgi.BundleHost;
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
	private GTable bundleStatusTable;
	private final BundleStatusModel bundleStatusModel;
	private JButton addButton;
	private JButton removeButton;
	private Color selectionColor;
	private GhidraFileChooser fileChooser;
	private GhidraFileFilter filter;

	public void notifyTableChanged() {
		bundleStatusTable.notifyTableChanged(new TableModelEvent(bundleStatusModel));
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

		bundleStatusTable = new GTable(bundleStatusModel);
		bundleStatusTable.setName("BUNDLEPATH_TABLE");
		bundleStatusTable.setSelectionBackground(selectionColor);
		bundleStatusTable.setSelectionForeground(Color.BLACK);
		bundleStatusTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

		// to allow custom cell renderers
		bundleStatusTable.setAutoCreateColumnsFromModel(false);

		int skinnyWidth = 50;

		TableColumn column =
			bundleStatusTable.getColumnModel().getColumn(bundleStatusModel.enabledColumn.index);
		column.setPreferredWidth(skinnyWidth);
		column.setMinWidth(skinnyWidth);
		column.setMaxWidth(skinnyWidth);
		column.setWidth(skinnyWidth);

		column = bundleStatusTable.getColumnModel().getColumn(bundleStatusModel.activeColumn.index);
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

		column = bundleStatusTable.getColumnModel().getColumn(bundleStatusModel.typeColumn.index);

		FontMetrics fontmetrics = panel.getFontMetrics(panel.getFont());
		column.setMaxWidth(10 +
			SwingUtilities.computeStringWidth(fontmetrics, BundlePath.Type.SourceDir.toString()));

		column = bundleStatusTable.getColumnModel().getColumn(bundleStatusModel.pathColumn.index);
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
			new GTableFilterPanel<>(bundleStatusTable, bundleStatusModel);

		JScrollPane scrollPane = new JScrollPane(bundleStatusTable);
		scrollPane.getViewport().setBackground(bundleStatusTable.getBackground());

		ListSelectionModel selModel = bundleStatusTable.getSelectionModel();
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
		int[] rows = bundleStatusTable.getSelectedRows();
		removeButton.setEnabled(rows.length > 0);
	}

	private void removeButtonAction() {
		int[] selectedRows = bundleStatusTable.getSelectedRows();
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
			bundleStatusTable.setRowSelectionInterval(row, row);
		}
		updateButtonsEnabled();
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
			bundleStatusModel.addNewPaths(files, true, false);
		}
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	public void dispose() {
		bundleStatusTable.dispose();
	}

	void selectRow(int rowIndex) {
		bundleStatusTable.selectRow(rowIndex);
	}

}
