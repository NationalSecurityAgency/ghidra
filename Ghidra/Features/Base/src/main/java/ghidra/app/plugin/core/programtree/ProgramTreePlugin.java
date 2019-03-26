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
package ghidra.app.plugin.core.programtree;

import java.util.*;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.CorePluginPackage;
import ghidra.app.cmd.module.*;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.TreeSelectionPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.*;
import ghidra.app.util.PluginConstants;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.util.GroupPath;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import ghidra.util.datastruct.StringKeyIndexer;
import ghidra.util.exception.AssertException;
import ghidra.util.task.RunManager;
import resources.Icons;
import resources.ResourceManager;

/**
 * Plugin that creates view provider services to show the trees in a program.
 * Notifies the view manager service when the view changes.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.TREE,
	shortDescription = "Show Program Tree Views",
	description = "This plugin shows a view for " +
			" each tree in the program. A tree can be organized into " +
			"folders and fragments.  The program tree view " +
			"controls what is displayed in the Code Browser.",
	servicesRequired = { ProgramManager.class, GoToService.class },
	servicesProvided = { ViewManagerService.class, ProgramTreeService.class, ViewProviderService.class },
	eventsConsumed = { ProgramActivatedPluginEvent.class, TreeSelectionPluginEvent.class },
	eventsProduced = { TreeSelectionPluginEvent.class /* event is generated in ProgramTree */ }
)
//@formatter:on
public class ProgramTreePlugin extends ProgramPlugin
		implements ProgramTreeService, OptionsChangeListener {

	private static final String PROGRAM_TREE_OPTION_NAME = "Program Tree";
	private static final String REPLACE_VIEW_OPTION_NAME = "Replace View on Double-click";
	private static final String REPLACE_VIEW_OPTION_DESCRIPTION = "When toggled on, a " +
		"double-click executes the \"Replace View\" action of the Program Tree.  When off, " +
		"a double-click navigates to the minimum address of the clicked fragment.";

	private static final String NUMBER_OF_VIEWS = "NumberOfViews";
	private static final String TREE_NAME = "TreeName";
	private static final String TOGGLE_STATE = "NavigationToggleState";

	private final static String OPEN_VIEW_ICON_NAME = "images/openSmallFolder.png";
	private final static String CREATE_ICON_NAME = "images/layout_add.png";
	private final static Icon NAVIGATION_ICON = Icons.NAVIGATE_ON_INCOMING_EVENT_ICON;

	private HashMap<String, TreeViewProvider> providerMap;// map of view providers, key is the name
	private GoToService goToService;
	private ViewManagerService viewManagerService;
	private ProgramTreeActionManager actionManager;
	private TreeViewProvider currentProvider;
	private ViewManagerComponentProvider viewProvider;
	private ProgramListener programListener;
	private TreeViewProvider defaultProvider;
	private boolean firingGoTo;
	private RunManager runManager;
	private DockingAction createAction;
	private DockingAction openAction;
	private ToggleDockingAction selectionToggleAction;
	private JPopupMenu popup;

	/**
	 * Tree signals that a user double-click will replace the view with the
	 * current node
	 */
	private boolean isReplaceViewMode = true;

	public ProgramTreePlugin(PluginTool tool) {
		super(tool, true, false);

		viewProvider = new ViewManagerComponentProvider(tool, getName());
		registerServiceProvided(ViewManagerService.class, viewProvider);

		providerMap = new HashMap<>();

		actionManager = new ProgramTreeActionManager(this);
		registerActions();
		programListener = new ProgramListener(this);
		runManager = new RunManager();
		runManager.showProgressBar(false);
		createActions();

		// show default provider
		defaultProvider = addTreeView(PluginConstants.DEFAULT_TREE_NAME);

		initOptions(tool.getOptions(PROGRAM_TREE_OPTION_NAME));

	}

	@Override
	public void serviceAdded(Class<?> interfaceClass, Object service) {
		if (interfaceClass != ViewProviderService.class) {
			return;
		}
		viewProvider.serviceAdded((ViewProviderService) service);
	}

	/**
	 * Notifies this plugin that service has been removed from the plugin tool.
	 */
	@Override
	public void serviceRemoved(Class<?> interfaceClass, Object service) {
		if (interfaceClass != ViewProviderService.class) {
			return;
		}
		viewProvider.serviceRemoved((ViewProviderService) service);
	}

	private void initOptions(ToolOptions options) {
		isReplaceViewMode = options.getBoolean(REPLACE_VIEW_OPTION_NAME, isReplaceViewMode);
		options.registerOption(REPLACE_VIEW_OPTION_NAME, isReplaceViewMode,
			new HelpLocation(getName(), "Replace_View"), REPLACE_VIEW_OPTION_DESCRIPTION);

		options.addOptionsChangeListener(this);
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		if (REPLACE_VIEW_OPTION_NAME.equals(optionName)) {
			isReplaceViewMode = (Boolean) newValue;
		}
	}

	@Override
	public String getViewedTreeName() {
		if (currentProvider != null) {
			return currentProvider.getViewName();
		}
		return null;
	}

	@Override
	public void setViewedTree(String treeName) {
		TreeViewProvider p = providerMap.get(treeName);
		if (currentProvider == p) {
			return;
		}
		if (p != null) {
			viewManagerService.setCurrentViewProvider(treeName);
			currentProvider = p;
		}
	}

	@Override
	public void setGroupSelection(GroupPath[] gps) {
		if (currentProvider != null) {
			currentProvider.setGroupSelection(gps);
		}
	}

	@Override
	public AddressSet getView() {
		if (currentProvider != null) {
			return currentProvider.getView();
		}
		return new AddressSet();
	}

	/**
	 * Tells a plugin that it is no longer needed. The plugin should remove
	 * itself from anything that it is registered to and release any resources.
	 */
	@Override
	public void dispose() {
		Iterator<String> iter = providerMap.keySet().iterator();
		while (iter.hasNext()) {
			String treeName = iter.next();
			TreeViewProvider provider = providerMap.get(treeName);
			deregisterService(ViewProviderService.class, provider);
			provider.dispose();
		}

		goToService = null;
		viewManagerService = null;
		if (currentProgram != null) {
			currentProgram.removeListener(programListener);
		}

		if (programListener != null) {
			programListener.dispose();
		}

		viewProvider.dispose();
		super.dispose();
	}

	@Override
	public Object getUndoRedoState(DomainObject domainObject) {
		if (domainObject != currentProgram) {
			return null;
		}
		SaveState saveState = new SaveState();
		writeDataState(saveState);
		return saveState;
	}

	@Override
	public void restoreUndoRedoState(DomainObject domainObject, Object state) {
		if (domainObject != currentProgram) {
			return;
		}
		SaveState saveState = (SaveState) state;
		readDataState(saveState);
	}

	/**
	 * Write data for plugin; writes the current selection.
	 */
	@Override
	public void writeDataState(SaveState saveState) {
		viewProvider.writeDataState(saveState);

		saveState.putInt(NUMBER_OF_VIEWS, providerMap.size());
		Iterator<String> iter = providerMap.keySet().iterator();
		int idx = 0;
		while (iter.hasNext()) {
			String treeName = iter.next();
			saveState.putString(TREE_NAME + "-" + idx, treeName);
			TreeViewProvider provider = providerMap.get(treeName);
			provider.writeDataState(saveState);
			++idx;
		}
		saveState.putBoolean(TOGGLE_STATE, selectionToggleAction.isSelected());
	}

	/**
	 * Read the data for the plugin upon deserialization; reads what should be
	 * the current selection in the tree.
	 */
	@Override
	public void readDataState(SaveState saveState) {
		viewProvider.readDataState(saveState);

		int numberOfViews = saveState.getInt(NUMBER_OF_VIEWS, 0);

		ArrayList<TreeViewProvider> viewList = new ArrayList<>();

		String[] treeNames = new String[numberOfViews];
		for (int i = 0; i < numberOfViews; i++) {
			treeNames[i] = saveState.getString(TREE_NAME + "-" + i, null);
		}
		ArrayList<TreeViewProvider> providerList = new ArrayList<>();
		for (String element : treeNames) {
			TreeViewProvider provider = providerMap.get(element);
			if (provider != null) {
				providerList.add(provider);
			}
		}

		for (String treeName : treeNames) {
			TreeViewProvider provider = providerMap.get(treeName);
			if (!treeExists(treeName)) {
				if (provider != null) {
					deregisterService(TreeViewProvider.class, provider);
					providerMap.remove(treeName);
					provider = null;
				}
			}
			else if (provider == null) {
				provider = addTreeView(treeName);
			}
			if (provider != null) {
				reloadTree(provider.getProgramDnDTree(), true);
				provider.readDataState(saveState);
				viewList.add(provider);
			}
		}
		removeStaleProviders(viewList);

		// If nothing is showing, then display the first program tree found.
		if (viewList.isEmpty()) {
			addTreeViews();
		}

		selectionToggleAction.setSelected(saveState.getBoolean(TOGGLE_STATE, true));
	}

	@Override
	public Object getTransientState() {
		SaveState ss = new SaveState();
		writeDataState(ss);
		return ss;
	}

	@Override
	public void restoreTransientState(Object state) {
		SaveState ss = (SaveState) state;
		readDataState(ss);
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent ev = (ProgramActivatedPluginEvent) event;
			viewProvider.setCurrentProgram(ev.getActiveProgram());
		}
		if (event instanceof TreeSelectionPluginEvent) {
			TreeSelectionPluginEvent ev = (TreeSelectionPluginEvent) event;
			String treeName = ev.getTreeName();
			TreeViewProvider provider = providerMap.get(treeName);
			if (provider == null) {
				return;
			}
			provider.setGroupSelection(ev.getGroupPaths());
		}
	}

	private void removeStaleProviders(ArrayList<TreeViewProvider> providerList) {
		HashMap<String, TreeViewProvider> map = new HashMap<>(providerMap);

		// remove views from the map that are not in the providerList
		Iterator<String> iter = map.keySet().iterator();
		while (iter.hasNext()) {
			String treeName = iter.next();
			TreeViewProvider provider = map.get(treeName);
			if (!providerList.contains(provider)) {
				deregisterService(ViewProviderService.class, provider);
				providerMap.remove(treeName);
			}
		}
	}

	/**
	 * Initialization method: Get the services we need.
	 */
	@Override
	protected void init() {
		goToService = tool.getService(GoToService.class);
		viewManagerService = tool.getService(ViewManagerService.class);
		if (viewManagerService == null) {
			throw new AssertException(
				"Program Tree Plugin could not find a " + "provider of the View Manager Service");
		}

		actionManager.clearSystemClipboard();
	}

	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(programListener);
		setProgram(null);
	}

	@Override
	protected void programActivated(Program program) {
		program.addListener(programListener);
		setProgram(program);
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		// select fragment that corresponds to the location
		if (currentProvider != null && selectionToggleAction.isSelected() && loc != null &&
			!firingGoTo && !actionManager.isReplacingView()) {
			currentProvider.selectPathsForLocation(loc);
		}
	}

	void treeViewAdded(String treeName) {
		TreeViewProvider provider = providerMap.get(treeName);
		if (provider == null) {
			addTreeView(treeName);
		}
	}

	void treeViewChanged(TreeViewProvider provider) {
		currentProvider = provider;
	}

	void doubleClick(ProgramNode node) {
		if (isReplaceViewMode) {
			currentProvider.replaceView(node);
		}

		// If the node is NOT the root node, just go to the location
		// of the first address in the fragment.  If it's root, we
		// need to get the lowest address of any item in the
		// current view.
		if (node.isFragment()) {
			goTo(node.getFragment());
		}
		else if (node.isModule()) {
			goTo(node.getModule().getAddressSet().getMinAddress());
		}
		else if (node.isRoot()) {
			goTo(this.getCurrentProvider().getView().getMinAddress());
		}
	}

	void goTo(ProgramFragment fragment) {

		Address minAddress = fragment.getMinAddress();

		if (minAddress == null) {
			return;// empty fragment
		}

		goTo(minAddress);
	}

	// called by JUnit tests
	TreeViewProvider getViewProvider(String viewName) {
		return providerMap.get(viewName);
	}

	ViewManagerService getViewManagerService() {
		return viewManagerService;
	}

	GoToService getGoToService() {
		return goToService;
	}

	ProgramTreeActionManager getActionManager() {
		return actionManager;
	}

	RunManager getRunManager() {
		return runManager;
	}

	DockingAction[] getToolBarActions() {
		return new DockingAction[] { createAction, openAction, selectionToggleAction };
	}

	// for JUnit testing
	JPopupMenu getPopupMenu() {
		return popup;
	}

	void enableActions(boolean enabled) {
		createAction.setEnabled(enabled);
		openAction.setEnabled(enabled);
		// toggle button is always enabled
	}

	/**
	 * Close the view if we are not trying to close the last view.
	 * 
	 * @param treeViewProvider
	 * @return true if the view can be closed
	 */
	boolean closeView(TreeViewProvider treeViewProvider) {
		String viewName = treeViewProvider.getViewName();
		if (providerMap.size() == 1) {
			tool.setStatusInfo("Cannot close last tree view");
			return false;
		}
		removeProvider(viewName);
		return true;

	}

	/**
	 * Notification that the view is deleted
	 * 
	 * @param treeViewProvider the deleted provider
	 * @return true if the view can be deleted
	 */
	boolean deleteView(TreeViewProvider treeViewProvider) {
		if (providerMap.size() == 1) {
			tool.setStatusInfo("Cannot delete the last tree view");
			return false;
		}
		String treeName = treeViewProvider.getViewName();
		DeleteTreeCmd cmd = new DeleteTreeCmd(treeName);
		if (!tool.execute(cmd, currentProgram)) {
			tool.setStatusInfo(cmd.getStatusMsg());
			return false;
		}
		return true;
	}

	/**
	 * Method renameView.
	 * 
	 * @param treeViewProvider
	 * @param newName
	 * @return boolean
	 */
	boolean renameView(TreeViewProvider treeViewProvider, String newName) {
		Listing listing = currentProgram.getListing();
		ProgramModule root = listing.getRootModule(newName);
		if (root == null) {
			String oldName = treeViewProvider.getViewName();

			if (providerMap.containsKey(newName)) {
				tool.setStatusInfo("Name " + newName + " alredy exists");
				return false;
			}

			// put an entry in the map by the new name, so that the callback from the
			// domainObjectChanged() will be able to find the tree in the map by the new name to
			// perform the update as required.
			providerMap.put(newName, treeViewProvider);

			RenameTreeCmd cmd = new RenameTreeCmd(oldName, newName);
			if (!tool.execute(cmd, currentProgram)) {
				tool.setStatusInfo(cmd.getStatusMsg());
				providerMap.remove(newName);// the change didn't work, remove the mapping
				return false;
			}

			providerMap.remove(oldName);
			providerMap.put(newName, treeViewProvider);

			if (defaultProvider == treeViewProvider) {
				defaultProvider = new TreeViewProvider(PluginConstants.DEFAULT_TREE_NAME, this);
			}
			else {
				reloadTree(treeViewProvider.getProgramDnDTree(), false);
			}
			return true;
		}
		tool.setStatusInfo("Tree named '" + newName + "' already exists");
		return false;
	}

	/**
	 * Method called by the program change listener when a tree is removed.
	 * 
	 * @param treeName name of tree that was removed
	 */
	void treeRemoved(String treeName) {
		removeProvider(treeName);
	}

	void treeRenamed(String oldName, String newName) {
		TreeViewProvider provider = providerMap.get(oldName);
		if (provider != null) {
			if (!provider.getViewName().equals(newName)) {
				providerMap.remove(oldName);
				providerMap.put(newName, provider);
				provider.setViewName(newName);
			}
		}
	}

	/**
	 * Get the program tree for the given tree name.
	 * 
	 * @param treeName name of tree in the program (also the name of the view)
	 * @return ProgramDnDTree tree, or null if there is no provider for the
	 *         given name
	 */
	ProgramDnDTree getTree(String treeName) {
		TreeViewProvider provider = providerMap.get(treeName);
		if (provider != null) {
			return provider.getProgramDnDTree();
		}
		return null;
	}

	/**
	 * Method getCurrentProvider.
	 * 
	 * @return TreeViewProvider
	 */
	TreeViewProvider getCurrentProvider() {
		return currentProvider;
	}

	int getNumberOfViews() {
		return providerMap.size();
	}

	/**
	 * Notification from the program domain object change listener that a
	 * fragment was moved; update all the view maps.
	 */
	void fragmentMoved() {
		Iterator<String> iter = providerMap.keySet().iterator();
		while (iter.hasNext()) {
			String treeName = iter.next();
			TreeViewProvider provider = providerMap.get(treeName);
			provider.notifyListeners();
		}
	}

	/**
	 * The program was restored from an Undo/Redo operation so reload it
	 * 
	 * @param checkRoot if true, only rebuild the tree if the root node is invalid; if false, 
	 *        force a rebuild of the tree 
	 */
	void reloadProgram(boolean checkRoot) {
		if (currentProgram == null) {
			// can happen when the SwingUpdateManager fires after the program has been closed
			return;
		}
		Listing listing = currentProgram.getListing();
		String[] treeNames = listing.getTreeNames();
		for (String element : treeNames) {
			ProgramDnDTree tree = getTree(element);
			if (tree != null) {
				reloadTree(tree, checkRoot);
			}
		}
	}

	private TreeViewProvider addTreeView(String treeName) {
		TreeViewProvider provider = providerMap.get(treeName);
		if (provider == null) {
			provider = new TreeViewProvider(treeName, this);
			providerMap.put(treeName, provider);
			if (currentProgram != null) {
				provider.setProgram(currentProgram);
			}
			registerServiceProvided(ViewProviderService.class, provider);
		}
		return provider;
	}

	void reloadTree(ProgramDnDTree tree) {
		reloadTree(tree, false);
	}

	/**
	 * Remember expansion and selection state, and the reload the program
	 * because it just got restored from an undo operation.
	 */
	private void reloadTree(final ProgramDnDTree tree, boolean checkRoot) {
		if (tree == null) {
			return;
		}
		ProgramNode rootNode = (ProgramNode) tree.getModel().getRoot();
		synchronized (rootNode) {
			if (checkRoot && rootNode.isValid(tree.getVersionTag())) {
				return;
			}
			ProgramModule rootModule =
				currentProgram.getListing().getRootModule(tree.getTreeName());
			if (rootModule != null && rootModule.getName().equals(rootNode.getName())) {
				tree.setBusyCursor(false);

				List<GroupPath> expandList = new ArrayList<>();// tree paths
				List<?> selectList = new ArrayList<>();
				List<?> nodeList = tree.getNodeList();
				List<?> origViewList = tree.getViewList();
				List<GroupPath> newViewList = new ArrayList<>();

				for (int i = 0; i < nodeList.size(); i++) {

					ProgramNode node = (ProgramNode) nodeList.get(i);
					TreePath path = node.getTreePath();
					GroupPath gp = node.getGroupPath();
					if (tree.isExpanded(path)) {
						expandList.add(gp);
					}
					if (origViewList.contains(path)) {
						newViewList.add(gp);
					}
				}
				tree.reload();

				for (int i = 0; i < selectList.size(); i++) {
					GroupPath gp = (GroupPath) selectList.get(i);
					tree.addGroupSelectionPath(gp);
				}

				for (int i = 0; i < expandList.size(); i++) {
					GroupPath gp = expandList.get(i);
					tree.expand(gp);
				}
				for (int i = 0; i < newViewList.size(); i++) {
					GroupPath gp = newViewList.get(i);
					tree.addGroupViewPath(gp);
				}
				if (newViewList.size() > 0 && tree.getViewList().size() == 0) {
					tree.addGroupViewPath(new GroupPath(rootNode.getName()));
				}
			}
			else {
				// set the root module to the view
				tree.reload();

				// set selection to root node
				tree.addToView(((ProgramNode) tree.getModel().getRoot()).getTreePath());
			}
			tree.fireTreeViewChanged();

			Listing listing = currentProgram.getListing();
			// check the name indexer
			StringKeyIndexer indexer = tree.getNameIndexer();
			String[] keys = indexer.getKeys();
			String treeName = tree.getTreeName();
			for (String element : keys) {
				ProgramModule m = listing.getModule(treeName, element);
				if (m != null) {
					continue;
				}
				ProgramFragment f = listing.getFragment(treeName, element);
				if (f == null) {
					// program does not contain any modules or
					// fragments with this name, so remove it from
					// the table.
					indexer.remove(element);
				}
			}
		}
	}

	/**
	 * Remove the provider with the given name and deregister the service.
	 */
	private void removeProvider(String providerName) {
		TreeViewProvider provider = providerMap.remove(providerName);
		if (provider != null) {
			deregisterService(ViewProviderService.class, provider);
		}
	}

	/**
	 * Return true if a tree with the given name exists in the program. If
	 * program is null and if the tree name is the default name, return true.
	 * 
	 * @param treeName tree name to look for
	 * @return boolean
	 */
	private boolean treeExists(String treeName) {
		if (currentProgram == null && treeName.equals(PluginConstants.DEFAULT_TREE_NAME)) {
			return true;
		}
		else if (currentProgram == null) {
			return false;
		}
		return currentProgram.getListing().getRootModule(treeName) != null;
	}

	private void registerActions() {
		DockingAction[] actions = actionManager.getActions();
		for (DockingAction element : actions) {
			tool.addAction(element);
		}
	}

	/**
	 * Set the program on each of the providers.
	 * 
	 * @param p program that is being opened; if p is null, then program is
	 *            being closed.
	 */
	private void setProgram(Program p) {

		Iterator<String> iter = providerMap.keySet().iterator();
		while (iter.hasNext()) {
			String treeName = iter.next();
			TreeViewProvider provider = providerMap.get(treeName);
			provider.setProgram(null);
		}
		iter = providerMap.keySet().iterator();
		while (iter.hasNext()) {
			String treeName = iter.next();
			TreeViewProvider provider = providerMap.get(treeName);
			deregisterService(ViewProviderService.class, provider);
		}
		providerMap.clear();
		actionManager.setProgram(p);
		if (p == null) {
			addDefaultProvider();
		}
		else {
			addTreeViews();
		}
	}

	/**
	 * Add the default provider that shows an "empty" program root.
	 */
	private void addDefaultProvider() {
		providerMap.put(PluginConstants.DEFAULT_TREE_NAME, defaultProvider);
		registerServiceProvided(ViewProviderService.class, defaultProvider);
	}

	/**
	 * Add tree views that are in the program; if no trees exist (unlikely),
	 * then add the default provider.
	 */
	private void addTreeViews() {
		deregisterService(ViewProviderService.class, defaultProvider);

		if (currentProgram == null) {
			// unexplained exception case seen in the wild
			addDefaultProvider();
			return;
		}

		String[] treeNames = currentProgram.getListing().getTreeNames();
		TreeViewProvider firstProvider = null;
		for (String element : treeNames) {
			TreeViewProvider p = addTreeView(element);
			if (firstProvider == null) {
				firstProvider = p;
			}
		}

		if (firstProvider == null) {
			addDefaultProvider();
			return;
		}

		viewManagerService.setCurrentViewProvider(firstProvider.getViewName());
		actionManager.setProgramTreeView(firstProvider.getViewName(),
			firstProvider.getProgramDnDTree());
	}

	/**
	 * Callback from the create default view action in the provider. Add a
	 * one-up number to the default name.
	 */
	private void createDefaultTreeView() {
		Listing listing = currentProgram.getListing();

		String baseName = PluginConstants.DEFAULT_TREE_NAME;
		int index = 1;
		String viewName = baseName;
		boolean done = false;
		while (!done) {
			ProgramModule root = listing.getRootModule(viewName);
			if (root == null) {
				CreateDefaultTreeCmd cmd = new CreateDefaultTreeCmd(viewName);
				if (!tool.execute(cmd, currentProgram)) {
					tool.setStatusInfo(cmd.getStatusMsg());
				}
				break;
			}
			viewName = baseName + "(" + index + ")";
			++index;
		}
		TreeViewProvider provider = addTreeView(viewName);
		viewManagerService.setCurrentViewProvider(viewName);
		currentProvider = provider;
	}

	/**
	 * Method called when the "Open Tree View" icon is hit; creates a window
	 * relative to the event source (in this case, a button) and shows the list
	 * of trees currently in the Program.
	 */
	private void openView(Object sourceObject) {
		JButton button = sourceObject instanceof JButton ? (JButton) sourceObject : null;
		final String[] treeNames = currentProgram.getListing().getTreeNames();
		popup = new JPopupMenu("Tree Views");
		for (int i = 0; i < treeNames.length; i++) {
			JMenuItem item = new JMenuItem(treeNames[i]);
			final int index = i;
			item.addActionListener(ev -> openView(treeNames[index]));
			popup.add(item);
		}

		if (treeNames.length == 0) {
			// should not get into this state...
			getTool().setStatusInfo("No views exist.");
		}
		else {
			popup.setBorder(new BevelBorder(BevelBorder.RAISED));
			if (button != null) {
				popup.show(button, button.getX() - button.getWidth(), button.getY());
			}
		}
	}

	/**
	 * Open an existing view in the program. If a provider already exists for
	 * the given tree name, make this the current view provider in the view
	 * manager service.
	 * 
	 * @param treeName name of tree
	 */
	private void openView(String treeName) {
		TreeViewProvider provider = providerMap.get(treeName);
		if (provider != null) {
			viewManagerService.setCurrentViewProvider(treeName);
			currentProvider = provider;
		}
		else {
			provider = addTreeView(treeName);
			viewManagerService.setCurrentViewProvider(treeName);
		}
	}

	/**
	 * Create the local actions that are shared among all the providers.
	 */
	private void createActions() {

		openAction = new DockingAction("Open Tree View", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				openView(context.getSourceObject());
			}
		};

		Icon icon = ResourceManager.loadImage(OPEN_VIEW_ICON_NAME);
		openAction.setToolBarData(new ToolBarData(icon));
		openAction.setEnabled(false);
		openAction.setDescription("Open Tree View");
		openAction.setHelpLocation(new HelpLocation(getName(), "Open_Tree_View"));

		createAction = new DockingAction("Create Default Tree View", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				createDefaultTreeView();
			}
		};

		icon = ResourceManager.loadImage(CREATE_ICON_NAME);
		createAction.setToolBarData(new ToolBarData(icon));
		createAction.setEnabled(false);
		createAction.setDescription(HTMLUtilities.toHTML("Create a new default tree view; shows\n" +
			"a fragment for each of the memory blocks."));
		createAction.setHelpLocation(new HelpLocation(getName(), "Create_Default_Tree_View"));

		selectionToggleAction = new ToggleDockingAction("Navigation", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (selectionToggleAction.isSelected()) {
					selectFragments();
				}
			}
		};
		selectionToggleAction.setEnabled(true);
		selectionToggleAction.setSelected(false);
		selectionToggleAction.setToolBarData(new ToolBarData(NAVIGATION_ICON));
		selectionToggleAction.setDescription(
			HTMLUtilities.toHTML("Toggle <b>On</b> means to select the fragment(s)\n" +
				"that corresponds to the current location."));
		selectionToggleAction.setHelpLocation(
			new HelpLocation(getName(), selectionToggleAction.getName()));
	}

	private void selectFragments() {
		if (currentLocation != null && currentProvider != null) {
			currentProvider.selectPathsForLocation(currentLocation);
		}
	}

}
