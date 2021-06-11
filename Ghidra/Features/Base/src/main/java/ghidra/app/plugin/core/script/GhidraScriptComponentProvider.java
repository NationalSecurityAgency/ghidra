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
package ghidra.app.plugin.core.script;

import java.awt.BorderLayout;
import java.awt.Rectangle;
import java.awt.event.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import org.apache.commons.lang3.StringUtils;

import docking.ActionContext;
import docking.action.KeyBindingData;
import docking.event.mouse.GMouseListenerAdapter;
import docking.widgets.OptionDialog;
import docking.widgets.table.*;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.BreadthFirstIterator;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.osgi.*;
import ghidra.app.script.*;
import ghidra.app.services.ConsoleService;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.task.*;
import resources.ResourceManager;
import util.CollectionUtils;
import utilities.util.FileUtilities;

public class GhidraScriptComponentProvider extends ComponentProviderAdapter {
	static final String WINDOW_GROUP = "Script Group";

	private static final double TOP_PREFERRED_RESIZE_WEIGHT = .80;
	private static final String DESCRIPTION_DIVIDER_LOCATION = "DESCRIPTION_DIVIDER_LOCATION";
	private static final String FILTER_TEXT = "FILTER_TEXT";

	private Map<ResourceFile, GhidraScriptEditorComponentProvider> editorMap = new HashMap<>();
	private final GhidraScriptMgrPlugin plugin;
	private JPanel component;
	private RootNode scriptRoot;
	private GTree scriptCategoryTree;
	private DraggableScriptTable scriptTable;
	private final GhidraScriptInfoManager infoManager;
	private GhidraScriptTableModel tableModel;
	private BundleStatusComponentProvider bundleStatusComponentProvider;
	private TaskListener taskListener = new ScriptTaskListener();
	private GhidraScriptActionManager actionManager;
	private GhidraTableFilterPanel<ResourceFile> tableFilterPanel;
	private JTextPane descriptionTextPane;
	private JSplitPane dataDescriptionSplit;
	private boolean hasBeenRefreshed = false;

	private TreePath previousPath;
	private String[] previousCategory;

	private ResourceFile lastRunScript;
	private WeakSet<RunScriptTask> runningScriptTaskSet =
		WeakDataStructureFactory.createCopyOnReadWeakSet();
	private TaskListener cleanupTaskSetListener = new TaskListener() {
		@Override
		public void taskCompleted(Task task) {
			runningScriptTaskSet.remove((RunScriptTask) task);
		}

		@Override
		public void taskCancelled(Task task) {
			runningScriptTaskSet.remove((RunScriptTask) task);
		}
	};

	private final BundleHost bundleHost;
	private final RefreshingBundleHostListener refreshingBundleHostListener =
		new RefreshingBundleHostListener();
	final private SwingUpdateManager refreshUpdateManager = new SwingUpdateManager(this::doRefresh);

	GhidraScriptComponentProvider(GhidraScriptMgrPlugin plugin, BundleHost bundleHost) {
		super(plugin.getTool(), "Script Manager", plugin.getName());

		this.plugin = plugin;
		this.bundleHost = bundleHost;
		this.infoManager = new GhidraScriptInfoManager();

		bundleStatusComponentProvider =
			new BundleStatusComponentProvider(plugin.getTool(), plugin.getName(), bundleHost);

		bundleHost.addListener(refreshingBundleHostListener);

		setHelpLocation(new HelpLocation(plugin.getName(), plugin.getName()));
		setIcon(ResourceManager.loadImage("images/play.png"));
		addToToolbar();
		setWindowGroup(WINDOW_GROUP);

		build();

		plugin.getTool().addComponentProvider(this, false);
		actionManager = new GhidraScriptActionManager(this, plugin, infoManager);
		updateTitle();
	}

	private void buildCategoryTree() {
		scriptRoot = new RootNode();

		scriptCategoryTree = new GTree(scriptRoot);
		scriptCategoryTree.setName("CATEGORY_TREE");
		scriptCategoryTree.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				maybeSelect(e);
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				maybeSelect(e);
			}

			private void maybeSelect(MouseEvent e) {
				if (e.isPopupTrigger()) {
					TreePath path = scriptCategoryTree.getPathForLocation(e.getX(), e.getY());
					scriptCategoryTree.setSelectionPath(path);
				}
			}
		});
		scriptCategoryTree.addGTreeSelectionListener(e -> {
			tableModel.fireTableDataChanged(); // trigger a refilter
			TreePath path = e.getPath();
			if (path != null) {
				scriptCategoryTree.expandPath(path);
			}
		});

		scriptCategoryTree.getSelectionModel()
				.setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
	}

	private void build() {
		buildCategoryTree();

		tableModel = new GhidraScriptTableModel(this, infoManager);

		scriptTable = new DraggableScriptTable(this, tableModel);
		scriptTable.setName("SCRIPT_TABLE");
		scriptTable.setAutoLookupColumn(tableModel.getNameColumnIndex());
		scriptTable.setRowSelectionAllowed(true);
		scriptTable.setAutoCreateColumnsFromModel(false);
		scriptTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		scriptTable.getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			tool.contextChanged(GhidraScriptComponentProvider.this);
			updateDescriptionPanel();
		});
		tableModel.addTableModelListener(e -> updateTitle());

		scriptTable.addMouseListener(new GMouseListenerAdapter() {
			@Override
			public void popupTriggered(MouseEvent e) {
				int displayRow = scriptTable.rowAtPoint(e.getPoint());
				if (displayRow >= 0) {
					scriptTable.setRowSelectionInterval(displayRow, displayRow);
				}
			}

			@Override
			public void doubleClickTriggered(MouseEvent e) {
				runScript();
			}
		});

		TableColumnModel columnModel = scriptTable.getColumnModel();
		// Set default column sizes
		for (int i = 0; i < columnModel.getColumnCount(); i++) {
			TableColumn column = columnModel.getColumn(i);
			String name = (String) column.getHeaderValue();
			switch (name) {
				case GhidraScriptTableModel.SCRIPT_ACTION_COLUMN_NAME:
					initializeUnresizableColumn(column, 50);
					break;
				case GhidraScriptTableModel.SCRIPT_STATUS_COLUMN_NAME:
					initializeUnresizableColumn(column, 50);
					break;
			}
		}

		JScrollPane scriptTableScroll = new JScrollPane(scriptTable);
		buildFilter();

		JPanel tablePanel = new JPanel(new BorderLayout());
		tablePanel.add(scriptTableScroll, BorderLayout.CENTER);
		tablePanel.add(tableFilterPanel, BorderLayout.SOUTH);

		JSplitPane treeTableSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
		treeTableSplit.setLeftComponent(scriptCategoryTree);
		treeTableSplit.setRightComponent(tablePanel);
		treeTableSplit.setDividerLocation(150);

		JComponent descriptionPanel = buildDescriptionComponent();

		dataDescriptionSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
		dataDescriptionSplit.setResizeWeight(TOP_PREFERRED_RESIZE_WEIGHT);
		dataDescriptionSplit.setName("dataDescriptionSplit");
		dataDescriptionSplit.setTopComponent(treeTableSplit);
		dataDescriptionSplit.setBottomComponent(descriptionPanel);

		component = new JPanel(new BorderLayout());
		component.add(dataDescriptionSplit, BorderLayout.CENTER);
	}

	/**
	 * Restore state for bundles, user actions, and filter.
	 *
	 * @param saveState the state object
	 */
	public void readConfigState(SaveState saveState) {
		bundleHost.restoreManagedBundleState(saveState, getTool());

		actionManager.restoreUserDefinedKeybindings(saveState);
		actionManager.restoreScriptsThatAreInTool(saveState);

		final int descriptionDividerLocation = saveState.getInt(DESCRIPTION_DIVIDER_LOCATION, 0);
		if (descriptionDividerLocation > 0) {

			ComponentListener listener = new ComponentAdapter() {
				@Override
				public void componentResized(ComponentEvent e) {
					dataDescriptionSplit.setResizeWeight(TOP_PREFERRED_RESIZE_WEIGHT); // give the top pane the most space
				}
			};
			component.addComponentListener(listener);

			dataDescriptionSplit.setDividerLocation(descriptionDividerLocation);
		}

		String filterText = saveState.getString(FILTER_TEXT, "");
		tableFilterPanel.setFilterText(filterText);
	}

	/**
	 * Save state for bundles, user actions, and filter.
	 *
	 * @param saveState the state object
	 */

	public void writeConfigState(SaveState saveState) {
		bundleHost.saveManagedBundleState(saveState);

		actionManager.saveUserDefinedKeybindings(saveState);
		actionManager.saveScriptsThatAreInTool(saveState);

		int dividerLocation = dataDescriptionSplit.getDividerLocation();
		if (dividerLocation > 0) {
			saveState.putInt(DESCRIPTION_DIVIDER_LOCATION, dividerLocation);
		}

		String filterText = tableFilterPanel.getFilterText();
		saveState.putString(FILTER_TEXT, filterText);
	}

	void dispose() {
		bundleHost.removeListener(refreshingBundleHostListener);
		editorMap.clear();
		scriptCategoryTree.dispose();
		scriptTable.dispose();
		tableFilterPanel.dispose();
		actionManager.dispose();
		bundleStatusComponentProvider.dispose();
	}

	/**
	 * @return the bundle host used for scripting, ultimately from {@link GhidraScriptUtil#getBundleHost()}
	 */
	public BundleHost getBundleHost() {
		return bundleHost;
	}

	GhidraScriptActionManager getActionManager() {
		return actionManager;
	}

	GhidraScriptInfoManager getInfoManager() {
		return infoManager;
	}

	Map<ResourceFile, GhidraScriptEditorComponentProvider> getEditorMap() {
		return editorMap;
	}

	void assignKeyBinding() {
		ResourceFile script = getSelectedScript();
		ScriptAction action = actionManager.createAction(script);

		KeyBindingInputDialog dialog = new KeyBindingInputDialog(getComponent(), script.getName(),
			action.getKeyBinding(), plugin, actionManager.getKeyBindingHelpLocation());
		if (dialog.isCancelled()) {
			plugin.getTool().setStatusInfo("User cancelled keybinding.");
			return;
		}
		action.setKeyBindingData(new KeyBindingData(dialog.getKeyStroke()));
		scriptTable.repaint();
	}

	void keyBindingUpdated() {
		scriptTable.repaint();
	}

	void renameScript() {
		ResourceFile script = getSelectedScript();
		ResourceFile directory = script.getParentFile();

		if (bundleHost.getExistingGhidraBundle(directory).isSystemBundle()) {
			Msg.showWarn(getClass(), getComponent(), getName(),
				"Unable to rename scripts in '" + directory + "'.");
			return;
		}
		if (isEditorOpen(script)) {
			Msg.showWarn(getClass(), getComponent(), "Unable to rename script",
				"The script is open for editing.\nPlease close the script and try again.");
			return;
		}

		GhidraScriptProvider provider = GhidraScriptUtil.getProvider(script);
		SaveDialog dialog = new SaveDialog(getComponent(), "Rename Script", this, script,
			actionManager.getRenameHelpLocation());
		if (dialog.isCancelled()) {
			plugin.getTool().setStatusInfo("User cancelled rename.");
			return;
		}

		ResourceFile renameFile = dialog.getFile();
		if (renameFile == null) {
			return;
		}

		if (renameFile.exists()) {
			Msg.showWarn(getClass(), getComponent(), "Unable to rename script",
				"Destination file already exists.");
			return;
		}

		enableScriptDirectory(renameFile.getParentFile());

		renameScriptByCopying(script, provider, renameFile);
	}

	/**
	 * Copy a script, renaming references to the class name.
	 *
	 * @param sourceScript source script
	 * @param destinationScript destination script
	 * @throws IOException if we fail to create temp, write contents, copy, or delete temp
	 */
	private void copyScript(ResourceFile sourceScript, ResourceFile destinationScript)
			throws IOException {
		String oldClassName = GhidraScriptUtil.getBaseName(sourceScript);
		String newClassName = GhidraScriptUtil.getBaseName(destinationScript);

		ResourceFile parentFile = sourceScript.getParentFile();
		ResourceFile temp = new ResourceFile(parentFile, "ghidraScript.tmp");
		try (PrintWriter writer = new PrintWriter(temp.getOutputStream())) {
			try (BufferedReader reader =
				new BufferedReader(new InputStreamReader(sourceScript.getInputStream()))) {
				while (true) {
					String line = reader.readLine();
					if (line == null) {
						break;
					}
					writer.println(line.replaceAll(oldClassName, newClassName));
				}
			}
		}
		FileUtilities.copyFile(temp, destinationScript, TaskMonitor.DUMMY);
		temp.delete();
	}

	private void renameScriptByCopying(ResourceFile script, GhidraScriptProvider provider,
			ResourceFile renameFile) {
		try {
			copyScript(script, renameFile);
		}
		catch (IOException e) {
			Msg.showError(getClass(), getComponent(), "Unable to rename script", e.getMessage());
			return;
		}

		if (!renameFile.exists()) {
			Msg.showWarn(getClass(), getComponent(), "Unable to rename script",
				"The rename operation failed.\nPlease check file permissions.");
			return;
		}

		if (!provider.deleteScript(script)) {
			Msg.showWarn(getClass(), getComponent(), "Unable to rename script",
				"Unable to remove original file.\nPlease check file permissions.");
			renameFile.delete();
			return;
		}
		infoManager.removeMetadata(script);

		if (actionManager.hasScriptAction(script)) {
			KeyStroke ks = actionManager.getKeyBinding(script);
			actionManager.removeAction(script);
			ScriptAction action = actionManager.createAction(renameFile);
			action.setKeyBindingData(new KeyBindingData(ks));
		}

		assert !infoManager.containsMetadata(renameFile) : "renamed script already has metadata";
		infoManager.getScriptInfo(renameFile);

		tableModel.switchScript(script, renameFile);
		setSelectedScript(renameFile);
	}

	JTable getTable() {
		return scriptTable;
	}

	int getScriptIndex(ResourceFile scriptFile) {
		return tableFilterPanel.getViewRow(tableModel.getScriptIndex(scriptFile));
	}

	ResourceFile getScriptAt(int viewRowIndex) {
		return tableModel.getScriptAt(tableFilterPanel.getModelRow(viewRowIndex));
	}

	/**
	 * @return enabled bundle paths from the scripting bundle host
	 */
	public List<ResourceFile> getScriptDirectories() {
		return bundleHost.getGhidraBundles()
				.stream()
				.filter(GhidraSourceBundle.class::isInstance)
				.filter(GhidraBundle::isEnabled)
				.map(GhidraBundle::getFile)
				.collect(Collectors.toList());
	}

	/**
	 * @return non-system bundle paths from the scripting bundle host
	 */
	public List<ResourceFile> getWritableScriptDirectories() {
		return bundleHost.getGhidraBundles()
				.stream()
				.filter(GhidraSourceBundle.class::isInstance)
				.filter(Predicate.not(GhidraBundle::isSystemBundle))
				.filter(GhidraBundle::isEnabled)
				.map(GhidraBundle::getFile)
				.collect(Collectors.toList());
	}

	boolean isEditorOpen(ResourceFile script) {
		GhidraScriptEditorComponentProvider editor = editorMap.get(script);
		return editor != null && plugin.getTool().isVisible(editor);
	}

	void deleteScript() {
		ResourceFile script = getSelectedScript();
		if (script == null) {
			return;
		}
		ResourceFile directory = script.getParentFile();

		if (bundleHost.getExistingGhidraBundle(directory).isSystemBundle()) {
			Msg.showWarn(getClass(), getComponent(), getName(),
				"Unable to delete scripts in '" + directory + "'.");
			return;
		}

		int result = OptionDialog.showYesNoDialog(getComponent(), getName(),
			"Are you sure you want to delete script '" + script.getName() + "'?");
		if (result == OptionDialog.OPTION_ONE) {
			if (removeScript(script)) {
				GhidraScriptProvider provider = GhidraScriptUtil.getProvider(script);
				if (provider.deleteScript(script)) {
					infoManager.removeMetadata(script);
					restoreSelection(script);
				}
				else {
					Msg.showInfo(getClass(), getComponent(), getName(),
						"Unable to delete script '" + script.getName() + "'\n" +
							"Please verify the file permissions.");
				}
			}
		}
	}

	private void restoreSelection(ResourceFile script) {
		int selectedRow = scriptTable.getSelectedRow();
		if (selectedRow < 0) {
			return;
		}

		int selectedModelRow = getModelRowForViewRow(selectedRow);
		if (tableModel.contains(selectedModelRow)) {
			scriptTable.setRowSelectionInterval(selectedRow, selectedRow);
			return;
		}

		if (tableModel.contains(selectedModelRow - 1)) {
			int viewRow = getViewRowForModelRow(selectedModelRow - 1);
			scriptTable.setRowSelectionInterval(viewRow, viewRow);
		}
	}

	void enableScriptDirectory(ResourceFile scriptDir) {
		bundleHost.enable(scriptDir);
		Msg.showInfo(this, getComponent(), "Script Path Added/Enabled",
			"The directory has been automatically enabled for use:\n" +
				scriptDir.getAbsolutePath());
	}

	void newScript() {
		try {
			PickProviderDialog providerDialog =
				new PickProviderDialog(getComponent(), actionManager.getNewHelpLocation());
			GhidraScriptProvider provider = providerDialog.getSelectedProvider();
			if (provider == null) {
				plugin.getTool().setStatusInfo("User cancelled creating a new script.");
				return;
			}

			// Create user script directory if it doesn't exist
			File userScriptsDir = new File(GhidraScriptUtil.USER_SCRIPTS_DIR);
			FileUtilities.checkedMkdirs(userScriptsDir);

			ResourceFile newFile = GhidraScriptUtil.createNewScript(provider,
				new ResourceFile(userScriptsDir), getScriptDirectories());
			SaveDialog dialog = new SaveNewScriptDialog(getComponent(), "New Script", this, newFile,
				actionManager.getNewHelpLocation());
			if (dialog.isCancelled()) {
				plugin.getTool().setStatusInfo("User cancelled creating a new script.");
				return;
			}
			newFile = dialog.getFile();

			enableScriptDirectory(newFile.getParentFile());

			String category = StringUtils.join(getSelectedCategoryPath(), ScriptInfo.DELIMITTER);
			provider.createNewScript(newFile, category);

			GhidraScriptEditorComponentProvider editor =
				new GhidraScriptEditorComponentProvider(plugin, this, newFile);
			editorMap.put(newFile, editor);

			// create the ScriptInfo object now, before the TableModelEvent handlers
			// attempt to use it.
			assert !infoManager.containsMetadata(newFile) : "new source already has metadata?";
			infoManager.getScriptInfo(newFile);

			tableModel.insertScript(newFile);

			int index = getScriptIndex(newFile);

			if (index >= 0) {
				scriptTable.setRowSelectionInterval(index, index);
				Rectangle rect = scriptTable.getCellRect(index, 0, true);
				scriptTable.scrollRectToVisible(rect);
			}
		}
		catch (IOException e) {
			Msg.showError(this, getComponent(), getName(), e.getMessage(), e);
		}
	}

	void runScript(String scriptName, TaskListener listener) {
		for (ResourceFile dir : bundleHost.getBundleFiles()) {
			if (dir.isDirectory()) {
				ResourceFile scriptSource = new ResourceFile(dir, scriptName);
				if (scriptSource.exists()) {
					runScript(scriptSource, listener);
					return;
				}
			}
		}
		throw new IllegalArgumentException("Script does not exist: " + scriptName);
	}

	void runScript(ResourceFile scriptFile) {
		runScript(scriptFile, taskListener);
	}

	void runScript(ResourceFile scriptFile, TaskListener listener) {
		lastRunScript = scriptFile;
		GhidraScript script = doGetScriptInstance(scriptFile);
		doRunScript(script, listener);
	}

	private GhidraScript doGetScriptInstance(ResourceFile scriptFile) {

		Supplier<GhidraScript> scriptSupplier = () -> {
			ConsoleService console = plugin.getConsoleService();
			return getScriptInstance(scriptFile, console);
		};

		if (!Swing.isSwingThread()) {
			return scriptSupplier.get();
		}

		AtomicReference<GhidraScript> ref = new AtomicReference<>();
		TaskBuilder.withRunnable(monitor -> ref.set(scriptSupplier.get()))
				.setTitle("Compiling Script Directory")
				.setLaunchDelay(1000)
				.launchModal();

		return ref.get();
	}

	private void doRunScript(GhidraScript script, TaskListener listener) {

		ConsoleService console = plugin.getConsoleService();
		RunScriptTask task = new RunScriptTask(script, plugin.getCurrentState(), console);
		runningScriptTaskSet.add(task);
		task.addTaskListener(listener);
		task.addTaskListener(cleanupTaskSetListener);
		new TaskLauncher(task, plugin.getTool().getToolFrame());
		tool.contextChanged(this); // some actions change after we run a script
		actionManager.notifyScriptWasRun();
	}

	private GhidraScript getScriptInstance(ResourceFile scriptFile, ConsoleService console) {
		String scriptName = scriptFile.getName();
		GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
		try {
			return provider.getScriptInstance(scriptFile, console.getStdErr());
		}
		catch (IllegalAccessException e) {
			console.addErrorMessage("", "Unable to access script: " + scriptName);
		}
		catch (InstantiationException e) {
			console.addErrorMessage("", "Unable to instantiate script: " + scriptName);
		}
		catch (ClassNotFoundException e) {
			console.addErrorMessage("", "Unable to locate script class: " + scriptName);
		}

		// show the error icon
		scriptTable.repaint();
		return null;
	}

	void runScript() {
		ResourceFile script = getSelectedScript();
		if (script != null) {
			runScript(script);
		}
	}

	void runLastScript() {
		if (lastRunScript != null) {
			runScript(lastRunScript);
		}
	}

	ResourceFile getLastRunScript() {
		return lastRunScript;
	}

	void sortScripts() {
		tableModel.fireTableDataChanged();
	}

	String[] getSelectedCategoryPath() {
		TreePath currentPath = scriptCategoryTree.getSelectionPath();

		String[] currentCategory = null;

		if (currentPath != null) {
			if (currentPath.equals(previousPath)) {
				return previousCategory;
			}
			if (currentPath.getPathCount() > 1) {
				GTreeNode node = (GTreeNode) currentPath.getLastPathComponent();
				currentCategory = getCategoryPath(node);
			}
		}

		previousPath = currentPath;
		previousCategory = currentCategory;

		return currentCategory;
	}

	private String[] getCategoryPath(GTreeNode node) {
		TreePath treePath = node.getTreePath();
		Object[] path = treePath.getPath();
		String[] categoryPath = new String[path.length - 1];
		for (int i = 0; i < categoryPath.length; i++) {
			categoryPath[i] = ((GTreeNode) path[i + 1]).getName();
		}
		return categoryPath;
	}

	void showBundleStatusComponent() {
		bundleStatusComponentProvider.setVisible(true);
	}

	/**
	 * refresh the list of scripts by listing files in each script directory.
	 *
	 * Note: this method can be used off the swing event thread.
	 */
	void refresh() {
		refreshUpdateManager.update();
	}

	/**
	 * refresh the list of scripts by listing files in each script directory.
	 *
	 * Note: this method MUST NOT BE USED off the swing event thread.
	 */
	private void doRefresh() {
		hasBeenRefreshed = true;

		TreePath preRefreshSelectionPath = scriptCategoryTree.getSelectionPath();

		updateAvailableScriptFilesForAllPaths();

		trimUnusedTreeCategories();

		scriptRoot.fireNodeStructureChanged(scriptRoot);
		if (preRefreshSelectionPath != null) {
			scriptCategoryTree.setSelectionPath(preRefreshSelectionPath);
		}
	}

	private void updateAvailableScriptFilesForAllPaths() {
		List<ResourceFile> scriptsToRemove = tableModel.getScripts();
		List<ResourceFile> scriptAccumulator = new ArrayList<>();
		for (ResourceFile bundleFile : getScriptDirectories()) {
			updateAvailableScriptFilesForDirectory(scriptsToRemove, scriptAccumulator, bundleFile);
		}

		// note: do this after the loop to prevent a flurry of table model update events
		// scriptinfo was created in updateAvailableScriptfilesForDirectory
		tableModel.insertScripts(scriptAccumulator);

		for (ResourceFile file : scriptsToRemove) {
			removeScript(file);
			infoManager.removeMetadata(file);
		}

		infoManager.refreshDuplicates();
		refreshScriptData();
	}

	private void updateAvailableScriptFilesForDirectory(List<ResourceFile> scriptsToRemove,
			List<ResourceFile> scriptAccumulator, ResourceFile directory) {
		ResourceFile[] files = directory.listFiles();
		if (files == null) {
			return;
		}

		for (ResourceFile scriptFile : files) {
			if (scriptFile.isFile() && GhidraScriptUtil.hasScriptProvider(scriptFile)) {
				if (getScriptIndex(scriptFile) == -1) {
					// note: we don't do this here, so we can prevent a flurry of table events
					// model.insertScript(element);
					scriptAccumulator.add(scriptFile);
				}
				// new ScriptInfo objects are created on performRefresh, e.g. on startup. Other
				// refresh operations might have old infos.
				// assert !GhidraScriptUtil.containsMetadata(scriptFile): "info already exists for script during refresh";
				ScriptInfo info = infoManager.getScriptInfo(scriptFile);
				String[] categoryPath = info.getCategory();
				scriptRoot.insert(categoryPath);
			}
			scriptsToRemove.remove(scriptFile);
		}

	}

	private void refreshScriptData() {
		List<ResourceFile> scripts = tableModel.getScripts();

		for (ResourceFile script : scripts) {
			// First get the ScriptInfo object and refresh, which will ensure any
			// info data (ie: script icons) will be reloaded.
			ScriptInfo info = infoManager.getExistingScriptInfo(script);
			info.refresh();

			ScriptAction scriptAction = actionManager.get(script);
			if (scriptAction != null) {
				scriptAction.refresh();
			}

		}
	}

	// note: we really should just rebuild the tree instead of using this method
	private void trimUnusedTreeCategories() {

		/*
		 			Unusual Algorithm
		
			The tree nodes represent categories, but do not contain nodes for individual
		 	scripts.  We wish to remove any of the tree nodes that no longer represent script
		 	categories.  (This can happen when a script is deleted or its category is changed.)
		 	This algorithm will assume that all nodes need to be deleted.  Then, each script is
		 	examined, using its category to mark a given node as 'safe'; that node's parents are
			also marked as safe.   Any nodes remaining unmarked have no reference script and
			will be deleted.
		 */

		// note: turn String[] to List<String> to use hashing
		Set<List<String>> categories = new HashSet<>();
		for (ScriptInfo info : infoManager.getScriptInfoIterable()) {
			String[] path = info.getCategory();
			List<String> category = Arrays.asList(path);
			for (int i = 1; i <= category.size(); i++) {
				categories.add(category.subList(0, i));
			}
		}

		List<GTreeNode> toDelete = new LinkedList<>();
		Iterator<GTreeNode> nodes = new BreadthFirstIterator(scriptRoot);
		for (GTreeNode node : CollectionUtils.asIterable(nodes)) {
			String[] path = getCategoryPath(node);
			List<String> category = Arrays.asList(path);
			if (!categories.contains(category)) {
				toDelete.add(node);
			}
		}

		for (GTreeNode node : toDelete) {
			GTreeNode parent = node.getParent();
			if (parent != null) {
				parent.removeNode(node);
			}
		}
	}

	GhidraScriptEditorComponentProvider getEditor() {
		ResourceFile script = getSelectedScript();
		return editorMap.get(script);
	}

	void editScriptBuiltin() {
		ResourceFile script = getSelectedScript();
		if (script == null) {
			plugin.getTool().setStatusInfo("Script is null.");
			return;
		}
		if (!script.exists()) {
			plugin.getTool().setStatusInfo("Script " + script.getName() + " does not exist.");
			return;
		}

		editScriptInGhidra(script);
	}

	void editScriptEclipse() {
		ResourceFile script = getSelectedScript();
		if (script == null) {
			plugin.getTool().setStatusInfo("Script is null.");
			return;
		}
		if (!script.exists()) {
			plugin.getTool().setStatusInfo("Script " + script.getName() + " does not exist.");
			return;
		}

		plugin.tryToEditFileInEclipse(script);
	}

	GhidraScriptEditorComponentProvider editScriptInGhidra(ResourceFile script) {
		GhidraScriptEditorComponentProvider editor = editorMap.get(script);
		if (editor == null) {
			try {
				editor = new GhidraScriptEditorComponentProvider(plugin, this, script);
				editorMap.put(script, editor);
				return editor;
			}
			catch (IOException e) {
				Msg.showError(this, getComponent(), "Error loading script", e.getMessage(), e);
				return null;
			}
		}
		plugin.getTool().showComponentProvider(editor, true);
		return editor;
	}

	/**
	 * reassign an existing editor component
	 *
	 * @param oldScript who the editor is currently assigned to
	 * @param newScript the new script to assign it to
	 */
	void switchEditor(ResourceFile oldScript, ResourceFile newScript) {
		GhidraScriptEditorComponentProvider editor = editorMap.get(oldScript);
		editorMap.put(newScript, editor);
		editorMap.remove(oldScript);
		// create corresponding info before inserting in table
		infoManager.getScriptInfo(newScript);
		tableModel.insertScript(newScript);
	}

	boolean removeScript(ResourceFile script) {
		// Always remove the script from the table, as it is no longer on disk.  If the user
		// has it open in the editor, then they may choose to leave the editor open, but they
		// will have to save that file if they want to keep the changes.
		tableModel.removeScript(script);

		if (!removeScriptEditor(script, true)) {
			return false; // user cancelled the closing of a dirty editor
		}

		actionManager.removeAction(script);
		infoManager.removeMetadata(script);
		return true;
	}

	boolean removeScriptEditor(ResourceFile script, boolean checkForSave) {
		GhidraScriptEditorComponentProvider editor = editorMap.get(script);
		if (editor == null) {
			return true;
		}

		if (checkForSave && editor.hasChanges()) {
			JComponent parentComponent = getComponent();
			if (plugin.getTool().isVisible(editor)) {
				parentComponent = editor.getComponent();
			}
			int result = OptionDialog.showYesNoDialog(parentComponent, getName(),
				"'" + script.getName() + "' has been modified. Discard changes?");
			if (result != OptionDialog.OPTION_ONE) {
				return false;
			}
		}

		plugin.getTool().removeComponentProvider(editor);
		editorMap.remove(script);
		return true;
	}

	private void initializeUnresizableColumn(TableColumn column, int width) {
		column.setPreferredWidth(width);
		column.setMinWidth(width);
		column.setMaxWidth(width);
		column.setResizable(false);
	}

	private void updateTitle() {
		StringBuilder buffy = new StringBuilder();
		int currentRowCount = tableFilterPanel.getRowCount();
		buffy.append(currentRowCount).append(" scripts ");
		if (tableFilterPanel.isFiltered()) {
			int unfilteredRowCount = tableFilterPanel.getUnfilteredRowCount();
			buffy.append(" (of ").append(unfilteredRowCount).append(')');
		}

		setSubTitle(buffy.toString());
	}

	void scriptUpdated(ResourceFile script) {
		ResourceFile selectedScript = getSelectedScript();
		if (selectedScript == null) {
			return; // no script selected, nothing to do
		}

		if (!selectedScript.equals(script)) {
			return; // the updated script is not the selected script, nothing to do
		}

		// the selected script has been changed, update the description panel
		updateDescriptionPanel();

		ScriptInfo info = infoManager.getExistingScriptInfo(script);
		updateCategoryTree(info.getCategory());
	}

	private void updateCategoryTree(String[] categoryPath) {
		scriptRoot.insert(categoryPath);
		trimUnusedTreeCategories();
	}

	private void buildFilter() {
		tableFilterPanel = new GhidraTableFilterPanel<>(scriptTable, tableModel);
		tableFilterPanel.setSecondaryFilter(new ScriptTableSecondaryFilter());
		tableFilterPanel.setFilterRowTransformer(new RowFilterTransformer<ResourceFile>() {
			List<String> list = new ArrayList<>();

			@Override
			public List<String> transform(ResourceFile script) {
				ScriptInfo info = infoManager.getExistingScriptInfo(script);
				list.clear();
				list.add(info.getName());
				list.add(info.getDescription());
				return list;
			}
		});
		tableFilterPanel.setToolTipText("<HTML>Include scripts with <b>Names</b> or " +
			"<b>Descriptions</b> containing this text.");
		tableFilterPanel.setFocusComponent(scriptCategoryTree);
	}

	private JComponent buildDescriptionComponent() {
		descriptionTextPane = new JTextPane();
		descriptionTextPane.setEditable(false);
		descriptionTextPane.setEditorKit(new HTMLEditorKit());
		JPanel descriptionPanel = new JPanel(new BorderLayout());
		descriptionPanel.add(descriptionTextPane);
		JScrollPane scrollPane = new JScrollPane(descriptionPanel);

		// since we use HTML, the default scroll amount is not correct (the line size in HTML is
		// larger than the default text line size)
		int newScrollIncrement = 5;
		JScrollBar verticalScrollBar = scrollPane.getVerticalScrollBar();
		verticalScrollBar.setUnitIncrement(newScrollIncrement);
		JScrollBar horizontalScrollBar = scrollPane.getHorizontalScrollBar();
		horizontalScrollBar.setUnitIncrement(newScrollIncrement);
		return scrollPane;
	}

	private void updateDescriptionPanel() {
		String text = "Error! no script info!";
		ResourceFile script = getSelectedScript();
		if (script != null) {
			ScriptInfo info = infoManager.getExistingScriptInfo(script);
			if (info != null) {
				text = info.getToolTipText();
			}
		}
		final String ftext = text;

		// have to do an invokeLater here, since the DefaultCaret class runs in an invokeLater,
		// which will overwrite our location setting
		SwingUtilities.invokeLater(() -> {
			descriptionTextPane.setText(ftext);
			descriptionTextPane.setCaretPosition(0);
		});
	}

	private int getModelRowForViewRow(int viewRow) {
		int rowCount = tableModel.getRowCount();
		if (rowCount == 0) {
			// this method can be called after a delete, with an index that is no longer valid
			return -1;
		}
		return tableFilterPanel.getModelRow(viewRow);
	}

	private int getViewRowForModelRow(int modelRow) {
		return tableFilterPanel.getViewRow(modelRow);
	}

	ResourceFile getSelectedScript() {
		int row = scriptTable.getSelectedRow();
		if (row < 0) {
			return null;
		}
		int modelRow = tableFilterPanel.getModelRow(row);
		return tableModel.getScriptAt(modelRow);
	}

	void setSelectedScript(ResourceFile script) {
		if (script == null) {
			return;
		}

		int scriptIndex = tableModel.getScriptIndex(script);

		int viewRow = tableFilterPanel.getViewRow(scriptIndex);

		if (viewRow == -1) {
			return;
		}

		scriptTable.setRowSelectionInterval(viewRow, viewRow);

		// make sure the script row is in the view (but don't scroll the x coordinate)
		Rectangle visibleRect = scriptTable.getVisibleRect();
		Rectangle cellRect = scriptTable.getCellRect(viewRow, 0, true);
		cellRect.width = 0;
		cellRect.x = visibleRect.x;
		if (visibleRect.contains(cellRect)) {
			return; // already in view
		}

		scriptTable.scrollRectToVisible(cellRect);
	}

	TaskListener getTaskListener() {
		return taskListener;
	}

	@Override
	public void componentShown() {
		if (!hasBeenRefreshed) {
			refresh();
		}
	}

	@Override
	public void componentActivated() {
		// put the user focus in the filter field, as often the user wishes to search for a script
		tableFilterPanel.requestFocus();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		Object source = scriptTable;
		if (event != null) {
			source = event.getSource();
			if (source instanceof JViewport) {
				JViewport viewport = (JViewport) source;
				source = viewport.getView();
			}
			if (!(source instanceof GTable)) {
				return null; // clicked somewhere not in the table
			}
		}

		int[] selectedRows = scriptTable.getSelectedRows();
		if (selectedRows.length != 1) {
			return new ActionContext(this, scriptTable); // can only work on one selection at a time
		}

		ResourceFile script = tableModel.getRowObject(selectedRows[0]);
		return new ActionContext(this, script, scriptTable);
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	void programClosed(Program program) {
		for (RunScriptTask scriptTask : runningScriptTaskSet) {
			if (program == scriptTask.getProgram()) {
				scriptTask.cancel();
			}
		}
	}

	/** passed to runScript, repaints scriptTable when a script completes */
	private class ScriptTaskListener implements TaskListener {
		@Override
		public void taskCancelled(Task task) {
			taskCompleted(task);
		}

		@Override
		public void taskCompleted(Task task) {
			Rectangle visibleRect = scriptTable.getVisibleRect();
			scriptTable.repaint(visibleRect);
		}
	}

	class RefreshingBundleHostListener implements BundleHostListener {

		@Override
		public void bundleBuilt(GhidraBundle bundle, String summary) {
			// on enable, build can happen before the refresh populates the info manager with
			// this bundle's scripts, so allow for the possibility and create the info here.
			if (bundle instanceof GhidraSourceBundle) {
				GhidraSourceBundle sourceBundle = (GhidraSourceBundle) bundle;
				ResourceFile sourceDirectory = sourceBundle.getFile();
				if (summary == null) {
					// a null summary means the build didn't change anything,
					// so use any errors from the last build
					for (ResourceFile sourceFile : sourceBundle.getAllErrors().keySet()) {
						if (sourceFile.getParentFile().equals(sourceDirectory)) {
							ScriptInfo scriptInfo = infoManager.getScriptInfo(sourceFile);
							scriptInfo.setCompileErrors(true);
						}
					}
				}
				else {
					for (ResourceFile sourceFile : sourceBundle.getNewSources()) {
						if (sourceFile.getParentFile().equals(sourceDirectory)) {
							ScriptInfo scriptInfo = infoManager.getScriptInfo(sourceFile);
							BuildError e = sourceBundle.getErrors(sourceFile);
							scriptInfo.setCompileErrors(e != null);
						}
					}
				}
				tableModel.fireTableDataChanged();
			}
		}

		@Override
		public void bundleEnablementChange(GhidraBundle bundle, boolean newEnablment) {
			if (bundle instanceof GhidraSourceBundle) {
				refresh();
			}
		}

		@Override
		public void bundleAdded(GhidraBundle bundle) {
			plugin.getTool().setConfigChanged(true);
			refresh();
		}

		@Override
		public void bundlesAdded(Collection<GhidraBundle> bundles) {
			plugin.getTool().setConfigChanged(true);
			refresh();
		}

		@Override
		public void bundleRemoved(GhidraBundle bundle) {
			plugin.getTool().setConfigChanged(true);
			refresh();
		}

		@Override
		public void bundlesRemoved(Collection<GhidraBundle> bundles) {
			plugin.getTool().setConfigChanged(true);
			refresh();
		}
	}

	/** Table filter that uses the state of the tree to further filter */
	private class ScriptTableSecondaryFilter implements TableFilter<ResourceFile> {

		@Override
		public boolean acceptsRow(ResourceFile script) {
			ScriptInfo info = infoManager.getExistingScriptInfo(script);
			String[] category = getSelectedCategoryPath();

			if (category == null) { // root node
				return matchesRootNode(info);
			}

			// matches the category?
			boolean isMatch = info.isCategory(category);
			return isMatch;
		}

		private boolean matchesRootNode(ScriptInfo info) {
			if (!scriptCategoryTree.isFiltered()) {
				return true; // without a filter, everything matches the root node
			}

			// with a filter, only things in the available children match the root node (this is
			// so filtering in the tree will show all matching results when the
			// root is selected, instead of all results).
			GTreeNode rootNode = scriptCategoryTree.getViewRoot();
			List<GTreeNode> children = rootNode.getChildren();
			for (GTreeNode node : children) {
				String[] path = getCategoryPath(node);
				if (info.isCategory(path)) {
					return true;
				}
			}
			return false;
		}

		@Override
		public boolean isSubFilterOf(TableFilter<?> tableFilter) {
			// For now the user does not have a way to change this filter, which means it will
			// never be a sub-filter of anything.
			return false;
		}
	}

}
