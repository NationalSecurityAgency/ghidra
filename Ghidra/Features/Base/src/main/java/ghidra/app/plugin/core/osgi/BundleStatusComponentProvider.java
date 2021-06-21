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
import java.io.PrintWriter;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.event.TableModelEvent;

import docking.action.builder.ActionBuilder;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.table.GTable;
import docking.widgets.table.GTableFilterPanel;
import generic.jar.ResourceFile;
import generic.util.Path;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.task.*;
import resources.Icons;
import resources.ResourceManager;

/**
 * component for managing OSGi bundle status
 */
public class BundleStatusComponentProvider extends ComponentProviderAdapter {

	static final String BUNDLE_GROUP = "0bundle group";
	static final String BUNDLE_LIST_GROUP = "1bundle list group";

	static final String PREFERENCE_LAST_SELECTED_BUNDLE = "LastGhidraBundle";

	private JPanel panel;
	private GTable bundleStatusTable;
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

		bundleStatusTableModel.addListener(new MyBundleStatusChangeRequestListener());

		this.filter = new GhidraFileFilter() {
			@Override
			public String getDescription() {
				return "Source code directory, bundle (*.jar), or bnd script (*.bnd)";
			}

			@Override
			public boolean accept(File file, GhidraFileChooserModel model) {
				return GhidraBundle.getType(file) != GhidraBundle.Type.INVALID;
			}
		};
		this.fileChooser = null;

		build();
		addToTool();
		createActions();
	}

	private void build() {
		panel = new JPanel(new BorderLayout(5, 5));

		bundleStatusTable = new GTable(bundleStatusTableModel);
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

		filterPanel = new GTableFilterPanel<>(bundleStatusTable, bundleStatusTableModel);

		JScrollPane scrollPane = new JScrollPane(bundleStatusTable);
		scrollPane.getViewport().setBackground(bundleStatusTable.getBackground());

		panel.add(filterPanel, BorderLayout.SOUTH);
		panel.add(scrollPane, BorderLayout.CENTER);
		panel.setPreferredSize(new Dimension(800, 400));
	}

	private void addBundlesAction(String actionName, String description, Icon icon,
			Runnable runnable) {

		new ActionBuilder(actionName, this.getName()).popupMenuPath(description)
				.popupMenuIcon(icon)
				.popupMenuGroup(BUNDLE_GROUP)
				.description(description)
				.enabled(false)
				.enabledWhen(context -> bundleStatusTable.getSelectedRows().length > 0)
				.onAction(context -> runnable.run())
				.buildAndInstallLocal(this);
	}

	private void createActions() {
		Icon icon = Icons.REFRESH_ICON;
		new ActionBuilder("RefreshBundles", this.getName()).popupMenuPath("Refresh all")
				.popupMenuIcon(icon)
				.popupMenuGroup(BUNDLE_LIST_GROUP)
				.toolBarIcon(icon)
				.toolBarGroup(BUNDLE_LIST_GROUP)
				.description("Refresh state by cleaning and reactivating all enabled bundles")
				.onAction(c -> doRefresh())
				.buildAndInstallLocal(this);

		addBundlesAction("EnableBundles", "Enable selected bundle(s)",
			ResourceManager.loadImage("images/media-playback-start.png"), this::doEnableBundles);

		addBundlesAction("DisableBundles", "Disable selected bundle(s)",
			ResourceManager.loadImage("images/media-playback-stop.png"), this::doDisableBundles);

		addBundlesAction("CleanBundles", "Clean selected bundle build cache(s)",
			ResourceManager.loadImage("images/erase16.png"), this::doCleanBundleBuildCaches);

		icon = ResourceManager.loadImage("images/Plus.png");
		new ActionBuilder("AddBundles", this.getName()).popupMenuPath("Add bundle(s)")
				.popupMenuIcon(icon)
				.popupMenuGroup(BUNDLE_LIST_GROUP)
				.toolBarIcon(icon)
				.toolBarGroup(BUNDLE_LIST_GROUP)
				.description("Display file chooser to add bundles to list")
				.onAction(c -> showAddBundlesFileChooser())
				.buildAndInstallLocal(this);

		icon = ResourceManager.loadImage("images/edit-delete.png");
		new ActionBuilder("RemoveBundles", this.getName())
				.popupMenuPath("Remove selected bundle(s)")
				.popupMenuIcon(icon)
				.popupMenuGroup(BUNDLE_LIST_GROUP)
				.toolBarIcon(icon)
				.toolBarGroup(BUNDLE_LIST_GROUP)
				.description("Remove selected bundle(s) from the list")
				.enabledWhen(c -> bundleStatusTable.getSelectedRows().length > 0)
				.onAction(c -> doRemoveBundles())
				.buildAndInstallLocal(this);
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

	private void doRefresh() {
		List<BundleStatus> statuses = bundleStatusTableModel.getModelData()
				.stream()
				.filter(BundleStatus::isEnabled)
				.collect(Collectors.toList());

		// clean them all..
		for (BundleStatus status : statuses) {
			GhidraBundle bundle = bundleHost.getExistingGhidraBundle(status.getFile());
			bundle.clean();
			status.setSummary("");
			try {
				bundleHost.deactivateSynchronously(bundle.getLocationIdentifier());
			}
			catch (GhidraBundleException | InterruptedException e) {
				Msg.error(this, "Error while deactivating bundle", e);
			}
		}

		// then activate them all
		new TaskLauncher(new EnableAndActivateBundlesTask("activating", statuses, true),
			getComponent(), 1000);
	}

	private void doCleanBundleBuildCaches() {
		int[] selectedModelRows = getSelectedModelRows();
		boolean anythingCleaned = false;
		for (BundleStatus status : bundleStatusTableModel.getRowObjects(selectedModelRows)) {
			anythingCleaned |= bundleHost.getExistingGhidraBundle(status.getFile()).clean();
			if (!status.getSummary().isEmpty()) {
				status.setSummary("");
				anythingCleaned |= true;
			}
		}
		if (anythingCleaned) {
			bundleStatusTableModel.fireTableDataChanged();
		}
	}

	private void doRemoveBundles() {
		int[] selectedModelRows = getSelectedModelRows();
		if (selectedModelRows == null || selectedModelRows.length == 0) {
			return;
		}
		new TaskLauncher(new RemoveBundlesTask("removing bundles", getSelectedStatuses()),
			getComponent(), 1000);
	}

	private void showAddBundlesFileChooser() {
		if (fileChooser == null) {
			fileChooser = new GhidraFileChooser(getComponent());
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
			String lastSelected = Preferences.getProperty(PREFERENCE_LAST_SELECTED_BUNDLE);
			if (lastSelected != null) {
				File lastSelectedFile = new File(lastSelected);
				fileChooser.setSelectedFile(lastSelectedFile);
			}
		}
		else {
			String lastSelected = Preferences.getProperty(PREFERENCE_LAST_SELECTED_BUNDLE);
			if (lastSelected != null) {
				File lastSelectedFile = new File(lastSelected);
				fileChooser.setSelectedFile(lastSelectedFile);
			}
			fileChooser.rescanCurrentDirectory();
		}

		List<File> files = fileChooser.getSelectedFiles();
		if (!files.isEmpty()) {
			Preferences.setProperty(PREFERENCE_LAST_SELECTED_BUNDLE,
				files.get(0).getAbsolutePath());
			List<ResourceFile> resourceFiles =
				files.stream().map(ResourceFile::new).collect(Collectors.toUnmodifiableList());
			Collection<GhidraBundle> bundles = bundleHost.add(resourceFiles, true, false);

			TaskLauncher.launchNonModal("activating new bundles", (monitor) -> {
				bundleHost.activateAll(bundles, monitor,
					getTool().getService(ConsoleService.class).getStdErr());
			});
		}
	}

	protected List<BundleStatus> getSelectedStatuses() {
		return bundleStatusTableModel.getRowObjects(getSelectedModelRows());
	}

	protected void doEnableBundles() {
		new TaskLauncher(new EnableAndActivateBundlesTask("enabling", getSelectedStatuses(), false),
			getComponent(), 1000);
	}

	protected void doDisableBundles() {
		new TaskLauncher(new DeactivateAndDisableBundlesTask("disabling", getSelectedStatuses()),
			getComponent(), 1000);
	}

	protected void doActivateDeactivateBundle(BundleStatus status, boolean activate) {
		status.setBusy(true);
		notifyTableRowChanged(status);
		new TaskLauncher(
			new ActivateDeactivateBundleTask(
				(activate ? "Activating" : "Deactivating ") + " bundle...", status, activate),
			null, 1000);
	}

	private void notifyTableRowChanged(BundleStatus status) {
		Swing.runIfSwingOrRunLater(() -> {
			int modelRowIndex = bundleStatusTableModel.getRowIndex(status);
			int viewRowIndex = filterPanel.getViewRow(modelRowIndex);
			bundleStatusTable
					.notifyTableChanged(new TableModelEvent(bundleStatusTableModel, viewRowIndex));
		});
	}

	private void notifyTableDataChanged() {
		Swing.runIfSwingOrRunLater(() -> {
			bundleStatusTable.notifyTableChanged(new TableModelEvent(bundleStatusTableModel));
		});
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	/**
	 * cleanup this component
	 */
	public void dispose() {
		filterPanel.dispose();
	}

	void selectModelRow(int modelRowIndex) {
		bundleStatusTable.selectRow(filterPanel.getViewRow(modelRowIndex));
	}

	/**
	 * This is for testing only!  during normal execution, statuses are only added through BundleHostListener bundle(s) added events.
	 * 
	 * <p>each new bundle will be enabled and writable
	 * 
	 * @param bundleFiles the files to use
	 */
	public void setBundleFilesForTesting(List<ResourceFile> bundleFiles) {
		bundleStatusTableModel.setModelData(bundleFiles.stream()
				.map(f -> new BundleStatus(f, true, false, null))
				.collect(Collectors.toList()));
	}

	private final class RemoveBundlesTask extends Task {
		private final DeactivateAndDisableBundlesTask deactivateBundlesTask;
		private final List<BundleStatus> statuses;

		private RemoveBundlesTask(String title, List<BundleStatus> statuses) {
			super(title);
			this.deactivateBundlesTask =
				new DeactivateAndDisableBundlesTask("deactivating", statuses);
			this.statuses = statuses;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			deactivateBundlesTask.run(monitor);
			monitor.checkCanceled();
			// partition bundles into system (bundles.get(true)) and non-system (bundles.get(false)).
			Map<Boolean, List<GhidraBundle>> bundles = statuses.stream()
					.map(bs -> bundleHost.getExistingGhidraBundle(bs.getFile()))
					.collect(Collectors.partitioningBy(GhidraBundle::isSystemBundle));

			List<GhidraBundle> systemBundles = bundles.get(true);
			if (!systemBundles.isEmpty()) {
				StringBuilder buff = new StringBuilder();
				for (GhidraBundle bundle : systemBundles) {
					buff.append(Path.toPathString(bundle.getFile()) + "\n");
				}
				Msg.showWarn(this, BundleStatusComponentProvider.this.getComponent(),
					"Unabled to remove", "System bundles cannot be removed:\n" + buff.toString());
			}
			bundleHost.remove(bundles.get(false));
		}
	}

	private class EnableAndActivateBundlesTask extends Task {
		private final List<BundleStatus> statuses;

		private final boolean inStages;

		/**
		 * A task to enable and activate bundles.
		 * 
		 * @param title the title
		 * @param statuses the bundle statuses
		 * @param inStages see {@link BundleHost#activateInStages}
		 */
		private EnableAndActivateBundlesTask(String title, List<BundleStatus> statuses,
				boolean inStages) {
			super(title, true, true, false);
			this.statuses = statuses;
			this.inStages = inStages;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {

			List<GhidraBundle> bundles = new ArrayList<>();
			for (BundleStatus status : statuses) {
				GhidraBundle bundle = bundleHost.getExistingGhidraBundle(status.getFile());
				if (!(bundle instanceof GhidraPlaceholderBundle)) {
					status.setBusy(true);
					if (status.getSummary().startsWith(BundleHost.ACTIVATING_BUNDLE_ERROR_MSG)) {
						status.setSummary("");
					}
					bundleHost.enable(bundle);
					bundles.add(bundle);
				}
			}
			notifyTableDataChanged();

			PrintWriter writer = getTool().getService(ConsoleService.class).getStdErr();
			if (inStages) {
				bundleHost.activateInStages(bundles, monitor, writer);
			}
			else {
				bundleHost.activateAll(bundles, monitor, writer);
			}

			boolean anybusy = false;
			for (BundleStatus status : statuses) {
				if (status.isBusy()) {
					anybusy = true;
					status.setBusy(false);
				}
			}
			if (anybusy) {
				notifyTableDataChanged();
			}
		}
	}

	private class DeactivateAndDisableBundlesTask extends Task {
		final List<BundleStatus> statuses;

		private DeactivateAndDisableBundlesTask(String title, List<BundleStatus> statuses) {
			super(title, true, true, false);
			this.statuses = statuses;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			List<GhidraBundle> bundles = statuses.stream()
					.filter(status -> status.isEnabled())
					.map(status -> bundleHost.getExistingGhidraBundle(status.getFile()))
					.collect(Collectors.toList());

			monitor.setMaximum(bundles.size());
			for (GhidraBundle bundle : bundles) {
				try {
					bundleHost.deactivateSynchronously(bundle.getLocationIdentifier());
					bundleHost.disable(bundle);
				}
				catch (GhidraBundleException | InterruptedException e) {
					Msg.error(this, "Error while deactivating and disabling bundle", e);
				}
				monitor.incrementProgress(1);
			}
		}
	}

	/*
	 * Activating/deactivating a single bundle doesn't require resolving dependents,
	 * so this task is slightly different from the others.
	 */
	private class ActivateDeactivateBundleTask extends Task {
		private final BundleStatus status;
		private final boolean activate;

		private ActivateDeactivateBundleTask(String title, BundleStatus status, boolean activate) {
			super(title);
			this.status = status;
			this.activate = activate;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			ConsoleService console = getTool().getService(ConsoleService.class);
			try {
				GhidraBundle bundle = bundleHost.getExistingGhidraBundle(status.getFile());
				if (activate) {
					if (status.getSummary().startsWith(BundleHost.ACTIVATING_BUNDLE_ERROR_MSG)) {
						status.setSummary("");
					}
					bundleHost.activateAll(Collections.singletonList(bundle), monitor,
						console.getStdErr());
				}
				else { // deactivate
					bundleHost.deactivateSynchronously(bundle.getLocationIdentifier());
				}
			}
			catch (Exception e) {
				status.setSummary(e.getMessage());
				Msg.error(this, "Error during activation/deactivation of bundle", e);
			}
			finally {
				status.setBusy(false);
				notifyTableRowChanged(status);
			}
		}
	}

	/**
	 * Listener that responds to change requests from the {@link BundleStatusTableModel}.
	 */
	private class MyBundleStatusChangeRequestListener implements BundleStatusChangeRequestListener {
		@Override
		public void bundleEnablementChangeRequest(BundleStatus status, boolean newValue) {
			GhidraBundle bundle = bundleHost.getExistingGhidraBundle(status.getFile());
			if (bundle instanceof GhidraPlaceholderBundle) {
				return;
			}
			if (newValue) {
				bundleHost.enable(bundle);
				doActivateDeactivateBundle(status, true);
			}
			else {
				if (status.isActive()) {
					doActivateDeactivateBundle(status, false);
				}
				bundleHost.disable(bundle);
			}
		}

		@Override
		public void bundleActivationChangeRequest(BundleStatus status, boolean newValue) {
			if (status.isEnabled()) {
				doActivateDeactivateBundle(status, newValue);
			}
		}
	}
}
