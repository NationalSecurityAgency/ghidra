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
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.table.TableColumn;

import docking.ActionContext;
import docking.action.*;
import docking.util.AnimationUtils;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.table.*;
import generic.jar.ResourceFile;
import generic.util.Path;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.task.*;
import resources.ResourceManager;

/**
 * component for managing OSGi bundle status
 */
public class BundleStatusComponentProvider extends ComponentProviderAdapter {
	static final String BUNDLE_GROUP = "0bundle group";
	static final String BUNDLE_LIST_GROUP = "1bundle list group";

	static final String PREFENCE_LAST_SELECTED_BUNDLE = "LastGhidraBundle";

	private JPanel panel;
	private LessFreneticGTable bundleStatusTable;
	private final BundleStatusTableModel bundleStatusTableModel;
	private GTableFilterPanel<BundleStatus> filterPanel;

	private GhidraFileChooser fileChooser;
	private GhidraFileFilter filter;
	private final BundleHost bundleHost;

	/**
	 * {@link BundleStatusComponentProvider} visualizes bundle status and exposes actions for
	 * adding, removing, enabling, disabling, activating, and deactivating bundles.
	 * 
	 * @param tool the tool
	 * @param owner the owner name
	 * @param bundleHost the bundle host
	 */
	public BundleStatusComponentProvider(PluginTool tool, String owner, BundleHost bundleHost) {
		super(tool, "BundleManager", owner);
		setHelpLocation(new HelpLocation("BundleManager", "BundleManager"));
		setTitle("Bundle Manager");

		this.bundleHost = bundleHost;
		this.bundleStatusTableModel = new BundleStatusTableModel(this, bundleHost);

		bundleStatusTableModel.addListener(new BundleStatusChangeRequestListener() {
			@Override
			public void bundleEnablementChangeRequest(BundleStatus status, boolean enabled) {
				GhidraBundle gb = bundleHost.getExistingGhidraBundle(status.getPath());
				if (gb instanceof GhidraPlaceholderBundle) {
					return;
				}
				if (enabled) {
					bundleHost.enable(gb);
				}
				else {
					if (status.isActive()) {
						startActivateDeactiveTask(status, false);
					}
					bundleHost.disable(gb);
				}
			}

			@Override
			public void bundleActivationChangeRequest(BundleStatus status, boolean newValue) {
				if (status.isEnabled()) {
					startActivateDeactiveTask(status, newValue);
				}
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
		addToTool();
		createActions();
	}

	private void build() {
		panel = new JPanel(new BorderLayout(5, 5));

		bundleStatusTable = new LessFreneticGTable(bundleStatusTableModel);
		bundleStatusTable.setName("BUNDLESTATUS_TABLE");
		bundleStatusTable.setSelectionBackground(new Color(204, 204, 255));
		bundleStatusTable.setSelectionForeground(Color.BLACK);
		bundleStatusTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

		// give actions a chance to update status when selection changed
		bundleStatusTable.getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			tool.contextChanged(BundleStatusComponentProvider.this);
		});

		// to allow custom cell renderers
		bundleStatusTable.setAutoCreateColumnsFromModel(false);

		configureTableColumns();
		filterPanel = new GTableFilterPanel<>(bundleStatusTable, bundleStatusTableModel);

		JScrollPane scrollPane = new JScrollPane(bundleStatusTable);
		scrollPane.getViewport().setBackground(bundleStatusTable.getBackground());

		panel.add(filterPanel, BorderLayout.SOUTH);
		panel.add(scrollPane, BorderLayout.CENTER);
		panel.setPreferredSize(new Dimension(800, 400));
	}

	private void configureTableColumns() {
		TableColumn column;

		int skinnyWidth = 60;
		// 
		column = bundleStatusTable.getColumnModel()
			.getColumn(bundleStatusTableModel.enabledColumn.index);
		column.setPreferredWidth(skinnyWidth);
		column.setMinWidth(skinnyWidth);
		column.setMaxWidth(skinnyWidth);
		column.setWidth(skinnyWidth);

		// 
		column =
			bundleStatusTable.getColumnModel().getColumn(bundleStatusTableModel.activeColumn.index);
		column.setPreferredWidth(skinnyWidth);
		column.setMinWidth(skinnyWidth);
		column.setMaxWidth(skinnyWidth);
		column.setWidth(skinnyWidth);
		column.setCellRenderer(new GBooleanCellRenderer() {
			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {
				BundleStatus status = (BundleStatus) data.getRowObject();
				Component x = super.getTableCellRendererComponent(data);
				if (status.isBusy()) {
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

		// 
		column =
			bundleStatusTable.getColumnModel().getColumn(bundleStatusTableModel.typeColumn.index);
		FontMetrics fontmetrics = panel.getFontMetrics(panel.getFont());
		column.setMaxWidth(10 +
			SwingUtilities.computeStringWidth(fontmetrics, GhidraBundle.Type.SourceDir.toString()));
		column =
			bundleStatusTable.getColumnModel().getColumn(bundleStatusTableModel.pathColumn.index);
		column.setCellRenderer(new GTableCellRenderer() {
			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {
				ResourceFile path = (ResourceFile) data.getValue();
				JLabel c = (JLabel) super.getTableCellRendererComponent(data);
				c.setText(Path.toPathString(path));
				GhidraBundle gb = bundleHost.getExistingGhidraBundle(path);
				if (gb == null || gb instanceof GhidraPlaceholderBundle || !path.exists()) {
					c.setForeground(Color.RED);
				}
				return c;
			}
		});
	}

	private void addBundlesAction(String actionName, String description, Icon icon,
			Runnable runnable) {
		DockingAction action = new DockingAction(actionName, this.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				runnable.run();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return bundleStatusTable.getSelectedRows().length > 0;
			}
		};
		action.setPopupMenuData(new MenuData(new String[] { description }, icon, BUNDLE_GROUP));
		action.setToolBarData(new ToolBarData(icon, BUNDLE_GROUP));
		action.setDescription(description);
		action.setEnabled(false);
		getTool().addLocalAction(this, action);

	}

	private void addBundleListAction(String actionName, String name, String description, Icon icon,
			Runnable runnable) {
		DockingAction action = new DockingAction(actionName, this.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				runnable.run();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return true;
			}
		};
		action.setPopupMenuData(new MenuData(new String[] { name }, icon, BUNDLE_LIST_GROUP));
		action.setToolBarData(new ToolBarData(icon, BUNDLE_LIST_GROUP));
		action.setDescription(description);
		action.setEnabled(true);
		getTool().addLocalAction(this, action);

	}

	private void createActions() {
		DockingAction action;

		addBundlesAction("ActivateBundles", "Activate bundle(s)",
			ResourceManager.loadImage("images/media-playback-start.png"), this::doActivateBundles);

		addBundlesAction("DeactivateBundles", "Deactivate bundle(s)",
			ResourceManager.loadImage("images/media-playback-stop.png"), this::doDeactivateBundles);

		addBundlesAction("CleanBundles", "Clean bundle(s)",
			ResourceManager.loadImage("images/erase16.png"), this::doClean);

		//
		action = new DockingAction("AddBundles", this.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				showAddBundlesFileChooser();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return true;
			}

		};
		Icon icon = ResourceManager.loadImage("images/Plus.png");
		action.setPopupMenuData(
			new MenuData(new String[] { "Add bundle(s)" }, icon, BUNDLE_LIST_GROUP));
		action.setToolBarData(new ToolBarData(icon, BUNDLE_LIST_GROUP));
		action.setDescription("Display file chooser to add bundles to list");
		action.setEnabled(true);
		getTool().addLocalAction(this, action);

		//
		icon = ResourceManager.loadImage("images/edit-delete.png");
		action = new DockingAction("RemoveBundles", this.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				doRemoveBundles();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return bundleStatusTable.getSelectedRows().length > 0;
			}

		};
		action.setPopupMenuData(
			new MenuData(new String[] { "Remove bundle(s)" }, icon, BUNDLE_LIST_GROUP));
		action.setToolBarData(new ToolBarData(icon, BUNDLE_LIST_GROUP));
		action.setDescription("Remove selected bundle(s) from the list");
		action.setEnabled(true);
		getTool().addLocalAction(this, action);
	}

	/**
	 * get the currently selected rows and translate to model rows
	 * 
	 * @return selected model rows
	 */
	int[] getSelectedModelRows() {
		int[] selectedRows = bundleStatusTable.getSelectedRows();
		if (selectedRows == null) {
			return null;
		}
		return Arrays.stream(selectedRows).map(filterPanel::getModelRow).toArray();
	}

	private void doClean() {
		int[] selectedModelRows = getSelectedModelRows();
		boolean anythingCleaned = false;
		for (BundleStatus bs : bundleStatusTableModel.getRowObjects(selectedModelRows)) {
			anythingCleaned |= bundleHost.getExistingGhidraBundle(bs.getPath()).clean();
			if (!bs.getSummary().isEmpty()) {
				bs.setSummary("");
				anythingCleaned |= true;
			}
		}
		if (anythingCleaned) {
			bundleStatusTableModel.fireTableDataChanged();
			AnimationUtils.shakeComponent(getComponent());
		}
	}

	private void doRemoveBundles() {
		int[] selectedModelRows = getSelectedModelRows();
		if (selectedModelRows == null || selectedModelRows.length == 0) {
			return;
		}
		doDeactivateBundles();

		Map<Boolean, List<GhidraBundle>> bundles =
			bundleStatusTableModel.getRowObjects(selectedModelRows)
				.stream()
				.map(bs -> bundleHost.getExistingGhidraBundle(bs.getPath()))
				.collect(Collectors.partitioningBy(gb -> gb.isSystemBundle()));
		List<GhidraBundle> systemBundles = bundles.get(true);
		if (!systemBundles.isEmpty()) {
			StringBuilder sb = new StringBuilder();
			for (GhidraBundle gb : systemBundles) {
				bundleHost.disable(gb);
				sb.append(gb.getPath() + "\n");
			}
			Msg.showWarn(this, this.getComponent(), "Unabled to remove",
				"System bundles cannot be removed:\n" + sb.toString());

		}

		bundleHost.remove(bundles.get(false));

	}

	private void showAddBundlesFileChooser() {
		if (fileChooser == null) {
			fileChooser = new GhidraFileChooser(panel);
			fileChooser.setMultiSelectionEnabled(true);
			fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_AND_DIRECTORIES);
			fileChooser.setTitle("Select Bundle(s)");
			// fileChooser.setApproveButtonToolTipText(title);
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
			String lastSelected = Preferences.getProperty(PREFENCE_LAST_SELECTED_BUNDLE);
			if (lastSelected != null) {
				File f = new File(lastSelected);
				fileChooser.setSelectedFile(f);
			}
		}
		else {
			String lastSelected = Preferences.getProperty(PREFENCE_LAST_SELECTED_BUNDLE);
			if (lastSelected != null) {
				File f = new File(lastSelected);
				fileChooser.setSelectedFile(f);
			}
			fileChooser.rescanCurrentDirectory();
		}

		List<File> files = fileChooser.getSelectedFiles();
		if (!files.isEmpty()) {
			Preferences.setProperty(PREFENCE_LAST_SELECTED_BUNDLE, files.get(0).getAbsolutePath());

			bundleHost.add(
				files.stream().map(ResourceFile::new).collect(Collectors.toUnmodifiableList()),
				true, false);
		}
	}

	protected void doActivateBundles() {
		int[] selectedModelRows = getSelectedModelRows();

		new TaskLauncher(new Task("activating", true, true, false) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				// suppress RowObjectSelectionManager repairs until after we're done
				bundleStatusTable.chill();

				List<BundleStatus> statuses =
					bundleStatusTableModel.getRowObjects(selectedModelRows)
						.stream()
						.filter(bs -> !bs.isActive())
						.collect(Collectors.toUnmodifiableList());

				List<GhidraBundle> gbs = new ArrayList<>();
				for (BundleStatus bs : statuses) {
					GhidraBundle gb = bundleHost.getExistingGhidraBundle(bs.getPath());
					if (!(gb instanceof GhidraPlaceholderBundle)) {
						bs.setBusy(true);
						bundleHost.enable(gb);
						gbs.add(gb);
					}
				}
				notifyTableDataChanged();

				bundleHost.activateAll(gbs, monitor,
					getTool().getService(ConsoleService.class).getStdErr());

				boolean anybusy = false;
				for (BundleStatus bs : statuses) {
					if (bs.isBusy()) {
						anybusy = true;
						bs.setBusy(false);
					}
				}
				if (anybusy) {
					notifyTableDataChanged();
				}

				bundleStatusTable.thaw();
			}
		}, getComponent(), 1000);
	}

	protected void doDeactivateBundles() {
		ConsoleService console = getTool().getService(ConsoleService.class);
		int[] selectedModelRows = getSelectedModelRows();

		new TaskLauncher(new Task("deactivating", true, true, false) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				List<GhidraBundle> gbs = bundleStatusTableModel.getRowObjects(selectedModelRows)
					.stream()
					.filter(bs -> bs.isActive())
					.map(bs -> bundleHost.getExistingGhidraBundle(bs.getPath()))
					.collect(Collectors.toList());

				monitor.setMaximum(gbs.size());
				for (GhidraBundle gb : gbs) {
					try {
						bundleHost.deactivateSynchronously(gb.getBundleLocation());
					}
					catch (GhidraBundleException | InterruptedException e) {
						e.printStackTrace(console.getStdErr());
					}
					monitor.incrementProgress(1);
				}
			}
		}, getComponent(), 1000);
	}

	protected void startActivateDeactiveTask(BundleStatus status, boolean activate) {
		status.setBusy(true);
		notifyTableRowChanged(status);
		ConsoleService console = getTool().getService(ConsoleService.class);

		new TaskLauncher(new Task((activate ? "Activating" : "Deactivating ") + " bundle...") {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				try {
					GhidraBundle gb = bundleHost.getExistingGhidraBundle(status.getPath());
					if (activate) {
						gb.build(console.getStdErr());
						bundleHost.activateSynchronously(gb.getBundleLocation());
					}
					else { // deactivate
						bundleHost.deactivateSynchronously(gb.getBundleLocation());
					}
				}
				catch (Exception e) {
					e.printStackTrace(console.getStdErr());
				}
				finally {
					status.setBusy(false);
					notifyTableRowChanged(status);
				}
			}
		}, null, 1000);
	}

	private void notifyTableRowChanged(BundleStatus status) {
		int modelRowIndex = bundleStatusTableModel.getRowIndex(status);
		int viewRowIndex = filterPanel.getViewRow(modelRowIndex);
		bundleStatusTable
			.notifyTableChanged(new TableModelEvent(bundleStatusTableModel, viewRowIndex));
	}

	private void notifyTableDataChanged() {
		bundleStatusTable.notifyTableChanged(new TableModelEvent(bundleStatusTableModel));
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

	/**
	 * cleanup this component
	 */
	public void dispose() {
		bundleStatusTable.dispose();
	}

	void selectModelRow(int modelRowIndex) {
		bundleStatusTable.selectRow(filterPanel.getViewRow(modelRowIndex));
	}

	/**
	 * This is for testing only!  during normal execution, statuses are only added through BundleHostListener bundle(s) added events.
	 * 
	 * each path is marked editable and non-readonly
	 * 
	 * @param bundlePaths the paths to use
	 */
	public void setPathsForTesting(List<ResourceFile> bundlePaths) {
		bundleStatusTableModel.setModelData(bundlePaths.stream()
			.map(f -> new BundleStatus(f, true, false, null))
			.collect(Collectors.toList()));
	}

}
