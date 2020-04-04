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
package ghidra.app.plugin.core.osgi;

import java.awt.*;
import java.io.File;
import java.util.Arrays;
import java.util.List;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.table.TableColumn;

import docking.ActionContext;
import docking.action.*;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.table.*;
import generic.jar.ResourceFile;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.task.*;
import resources.Icons;
import resources.ResourceManager;

/**
 * component for managing OSGi bundle status
 */
public class BundleStatusProvider extends ComponentProviderAdapter {
	static String preferenceForLastSelectedBundle = "LastGhidraScriptBundle";

	private JPanel panel;
	private GTable bundleStatusTable;
	private final BundleStatusModel bundleStatusModel;
	private Color selectionColor;
	private GhidraFileChooser fileChooser;
	private GhidraFileFilter filter;
	private final BundleHost bundleHost;

	public void notifyTableChanged() {
		bundleStatusTable.notifyTableChanged(new TableModelEvent(bundleStatusModel));
	}

	public BundleStatusProvider(PluginTool tool, String owner) {
		super(tool, "Bundle Status Manager", owner);
		this.bundleHost = BundleHost.getInstance();
		this.bundleStatusModel = new BundleStatusModel(this, bundleHost);
		bundleStatusModel.addListener(new BundleStatusListener() {
			@Override
			public void bundleEnablementChanged(BundleStatus status, boolean enabled) {
				if (!enabled && status.isActive()) {
					startActivateDeactiveTask(status, false);
				}
			}

			@Override
			public void bundleActivationChanged(BundleStatus status, boolean newValue) {
				startActivateDeactiveTask(status, newValue);
			}
		});

		this.filter = new GhidraFileFilter() {
			@Override
			public String getDescription() {
				return "Source code directory, bundle (*.jar), or bnd script (*.bnd)";
			}

			@Override
			public boolean accept(File path, GhidraFileChooserModel model) {
				return GhidraBundle.getType(path) != GhidraBundle.Type.INVALID;
			}
		};
		this.fileChooser = null;

		build();
		//getTool().addComponentProvider(this, false);
		addToTool();
		createActions();
	}

	public BundleStatusModel getModel() {
		return bundleStatusModel;
	}

	private void build() {
		panel = new JPanel(new BorderLayout(5, 5));

		selectionColor = new Color(204, 204, 255);

		bundleStatusTable = new GTable(bundleStatusModel);
		bundleStatusTable.setName("BUNDLESTATUS_TABLE");
		bundleStatusTable.setSelectionBackground(selectionColor);
		bundleStatusTable.setSelectionForeground(Color.BLACK);
		bundleStatusTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

		bundleStatusTable.getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			tool.contextChanged(BundleStatusProvider.this);
		});

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
				BundleStatus status = (BundleStatus) data.getRowObject();
				Component x = super.getTableCellRendererComponent(data);
				if (status.getBusy()) {
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
			SwingUtilities.computeStringWidth(fontmetrics, GhidraBundle.Type.SourceDir.toString()));

		column = bundleStatusTable.getColumnModel().getColumn(bundleStatusModel.pathColumn.index);
		column.setCellRenderer(new GTableCellRenderer() {
			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {
				JLabel c = (JLabel) super.getTableCellRendererComponent(data);

				ResourceFile path = (ResourceFile) data.getValue();
				if (!path.exists()) {
					c.setForeground(Color.RED);
				}
				return c;
			}
		});

		GTableFilterPanel<BundleStatus> filterPanel =
			new GTableFilterPanel<>(bundleStatusTable, bundleStatusModel);

		JScrollPane scrollPane = new JScrollPane(bundleStatusTable);
		scrollPane.getViewport().setBackground(bundleStatusTable.getBackground());

		panel.add(filterPanel, BorderLayout.SOUTH);
		panel.add(scrollPane, BorderLayout.CENTER);
		panel.setPreferredSize(new Dimension(800, 400));
	}

	private void createActions() {
		DockingAction action;
		//

		action = new DockingAction("Clean", this.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				int[] selectedRows = bundleStatusTable.getSelectedRows();
				for (BundleStatus o : bundleStatusModel.getRowObjects(selectedRows)) {
					bundleHost.getGhidraBundle(o.getPath()).clean();
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return bundleStatusTable.getSelectedRows().length > 0;
			}

		};
		action.setPopupMenuData(
			new MenuData(new String[] { "Clean bundle(s)" }, Icons.REFRESH_ICON, null));
		action.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));

		action.setDescription("Clean selected bundles");
		action.setEnabled(false);
		getTool().addLocalAction(this, action);

		// 
		action = new DockingAction("AddBundle", this.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				addBundlesAction();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return true;
			}

		};
		action.setPopupMenuData(new MenuData(new String[] { "Add bundle" },
			ResourceManager.loadImage("images/Plus.png"), null));
		action.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/Plus.png"), null));

		action.setDescription("Display file chooser to add bundles to list");
		action.setEnabled(true);
		getTool().addLocalAction(this, action);

		// 
		action = new DockingAction("RemoveBundle", this.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				removeBundlesAction();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return bundleStatusTable.getSelectedRows().length > 0;
			}

		};
		action.setPopupMenuData(new MenuData(new String[] { "Remove bundle(s)" },
			ResourceManager.loadImage("images/edit-delete.png"), null));
		action.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/edit-delete.png"), null));

		action.setDescription("Remove selected bundles");
		action.setEnabled(true);
		getTool().addLocalAction(this, action);
	}

	private void removeBundlesAction() {
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
	}

	private void addBundlesAction() {
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

	/*
	@Override
	public ActionContext getActionContext(MouseEvent event) {
		return new ActionContext(this, bundleStatusTable.getSelectedRows(), bundleStatusTable);
	}
	*/

	public void dispose() {
		bundleStatusTable.dispose();
	}

	private void startActivateDeactiveTask(BundleStatus status, boolean activate) {
		status.setBusy(true);
		notifyTableChanged();
		ConsoleService console = getTool().getService(ConsoleService.class);

		new TaskLauncher(new Task((activate ? "Activating" : "Deactivating ") + " bundle...") {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				try {
					GhidraBundle sb = bundleHost.getGhidraBundle(status.getPath());
					if (activate) {
						sb.build(console.getStdErr());
						bundleHost.activateSynchronously(sb.getBundleLoc());
					}
					else { // deactivate
						bundleHost.deactivateSynchronously(sb.getBundleLoc());
					}
				}
				catch (Exception e) {
					e.printStackTrace(console.getStdErr());
					status.setActive(!activate);

					Msg.showError(this, getComponent(), "bundle activation failed", e.getMessage());
				}
				finally {
					status.setBusy(false);
					notifyTableChanged();
				}
			}
		}, null, 1000);
	}

	// XXX workaround for RowObjectSelection.. repair
	void selectRow(int rowIndex) {
		bundleStatusTable.selectRow(rowIndex);
	}

}
