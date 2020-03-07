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
package ghidra.app.plugin.core.functioncompare;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.*;
import docking.help.Help;
import docking.help.HelpService;
import docking.widgets.fieldpanel.internal.FieldPanelCoordinator;
import docking.widgets.tabbedpane.DockingTabRenderer;
import ghidra.app.util.viewer.listingpanel.ListingCodeComparisonPanel;
import ghidra.app.util.viewer.util.CodeComparisonPanel;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import resources.ResourceManager;

/**
 * A panel for displaying {@link Function functions}, {@link Data data}, or 
 * {@link AddressSet address sets} side-by-side for comparison purposes
 * <p>
 * Note: This is strictly for a one-to-one comparison; if multiple items are to
 * be compared, use a {@link MultiFunctionComparisonPanel}
 */
public class FunctionComparisonPanel extends JPanel implements ChangeListener {

	private FunctionComparisonData leftComparisonData;
	private FunctionComparisonData rightComparisonData;

	private static final String DEFAULT_CODE_COMPARISON_VIEW = ListingCodeComparisonPanel.TITLE;
	private static final String COMPARISON_VIEW_DISPLAYED = "COMPARISON_VIEW_DISPLAYED";
	private static final String CODE_COMPARISON_LOCK_SCROLLING_TOGETHER =
		"CODE_COMPARISON_LOCK_SCROLLING_TOGETHER";

	private static final HelpService help = Help.getHelpService();
	private static final String HELP_TOPIC = "FunctionComparison";

	private static final Icon SYNC_SCROLLING_ICON = ResourceManager.loadImage("images/lock.gif");
	private static final Icon UNSYNC_SCROLLING_ICON =
		ResourceManager.loadImage("images/unlock.gif");
	private static final String SCROLLING_GROUP = "A9_SCROLLING";
	private static final String DUAL_SCROLLING_ACTION_GROUP = "DualScrolling";
	private static final String DUAL_SCROLLING_HELP_TOPIC = "FunctionComparison";

	private JTabbedPane tabbedPane;
	private Map<String, JComponent> tabNameToComponentMap;
	protected PluginTool tool;
	protected ComponentProviderAdapter provider;
	private List<CodeComparisonPanel<? extends FieldPanelCoordinator>> codeComparisonPanels;
	private ToggleScrollLockAction toggleScrollLockAction;
	private boolean syncScrolling = false;

	/**
	 * Constructor
	 * 
	 * @param provider the GUI provider that includes this panel
	 * @param tool the tool containing this panel
	 * @param leftFunction the function displayed in the left side of the panel
	 * @param rightFunction the function displayed in the right side of the panel
	 */
	public FunctionComparisonPanel(ComponentProviderAdapter provider, PluginTool tool,
			Function leftFunction, Function rightFunction) {
		this.provider = provider;
		this.tool = tool;
		this.leftComparisonData = new FunctionComparisonData();
		this.rightComparisonData = new FunctionComparisonData();
		this.leftComparisonData.setFunction(leftFunction);
		this.rightComparisonData.setFunction(rightFunction);
		this.codeComparisonPanels = getCodeComparisonPanels();
		tabNameToComponentMap = new HashMap<>();
		createMainPanel();
		createActions();
		setScrollingSyncState(true);
		help.registerHelp(this, new HelpLocation(HELP_TOPIC, "Function Comparison"));
	}

	/**
	 * Load the given functions into the views of this panel
	 * 
	 * @param leftFunction The function for the left side of the panel
	 * @param rightFunction The function for the right side of the panel
	 */
	public void loadFunctions(Function leftFunction, Function rightFunction) {
		leftComparisonData.setFunction(leftFunction);
		rightComparisonData.setFunction(rightFunction);

		CodeComparisonPanel<? extends FieldPanelCoordinator> activePanel =
			getActiveComparisonPanel();
		if (activePanel != null) {
			activePanel.loadFunctions(leftComparisonData.getFunction(),
				rightComparisonData.getFunction());
		}
	}

	/**
	 * Load the given data into the views of this panel
	 * 
	 * @param leftData The data for the left side of the panel
	 * @param rightData The data for the right side of the panel
	 */
	public void loadData(Data leftData, Data rightData) {
		leftComparisonData.setData(leftData);
		rightComparisonData.setData(rightData);

		CodeComparisonPanel<? extends FieldPanelCoordinator> activePanel =
			getActiveComparisonPanel();
		if (activePanel != null) {
			activePanel.loadData(leftComparisonData.getData(),
				rightComparisonData.getData());
		}
	}

	/**
	 * Load the given addresses of the indicated programs into the views of 
	 * this panel
	 * 
	 * @param leftProgram the program for the left side of the panel
	 * @param rightProgram the program for the right side of the panel
	 * @param leftAddresses addresses for the info to display in the left side 
	 * of the panel
	 * @param rightAddresses addresses for the info to display in the right 
	 * side of the panel
	 */
	public void loadAddresses(Program leftProgram, Program rightProgram,
			AddressSetView leftAddresses, AddressSetView rightAddresses) {
		leftComparisonData.setAddressSet(leftAddresses);
		rightComparisonData.setAddressSet(rightAddresses);
		leftComparisonData.setProgram(leftProgram);
		rightComparisonData.setProgram(rightProgram);
		CodeComparisonPanel<? extends FieldPanelCoordinator> activePanel =
			getActiveComparisonPanel();
		if (activePanel != null) {
			activePanel.loadAddresses(leftComparisonData.getProgram(),
				rightComparisonData.getProgram(), leftComparisonData.getAddressSet(),
				rightComparisonData.getAddressSet());
		}
	}

	/**
	 * Get the actions for this FunctionComparisonPanel
	 * 
	 * @return an array containing the actions
	 */
	public DockingAction[] getActions() {
		DockingAction[] actions = new DockingAction[] { toggleScrollLockAction };
		return actions;
	}

	/**
	 * Gets a description to help distinguish this comparison panel from others
	 * 
	 * @return the description
	 */
	public String getDescription() {
		Function leftFunc = leftComparisonData.getFunction();
		Function rightFunc = rightComparisonData.getFunction();
		Data leftData = leftComparisonData.getData();
		Data rightData = rightComparisonData.getData();

		if (leftFunc != null && rightFunc != null) {
			return leftFunc.getName(true) + " & " +
				rightFunc.getName(true);
		}
		if (leftData != null && rightData != null) {
			return leftData.getDataType().getName() + " & " +
				rightData.getDataType().getName();
		}

		// Otherwise give a simple description for address sets
		return "Nothing selected";
	}

	/**
	 * Clear both sides of this panel
	 */
	public void clear() {
		leftComparisonData.clear();
		rightComparisonData.clear();

		// Setting the addresses to be displayed to null effectively clears
		// the display
		CodeComparisonPanel<? extends FieldPanelCoordinator> activePanel =
			getActiveComparisonPanel();
		if (activePanel != null) {
			activePanel.loadAddresses(null, null, null, null);
		}
	}

	/**
	 * Returns true if the comparison window has no information to display in
	 * either the left or right panel
	 * 
	 * @return true if the comparison window has no information to display
	 */
	public boolean isEmpty() {
		return leftComparisonData.isEmpty() || rightComparisonData.isEmpty();
	}

	/**
	 * Gets the ListingCodeComparisonPanel being displayed by this panel 
	 * if one exists
	 * 
	 * @return the comparison panel or null
	 */
	public ListingCodeComparisonPanel getDualListingPanel() {
		for (CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel : codeComparisonPanels) {
			JComponent component = codeComparisonPanel.getComponent();
			if (component instanceof ListingCodeComparisonPanel) {
				return (ListingCodeComparisonPanel) component;
			}
		}
		return null;
	}

	@Override
	public void stateChanged(ChangeEvent e) {
		tabChanged();
	}

	/**
	 * Refreshes the contents of the panel
	 */
	public void reload() {
		// do nothing by default; override in subs if necessary
	}

	/**
	 * Set the current tabbed panel to be the component with the given name
	 * 
	 * @param name name of view to set as the current tab
	 * @return true if the named view was found in the provider map
	 */
	public boolean setCurrentTabbedComponent(String name) {

		JComponent component = tabNameToComponentMap.get(name);
		if (component != null) {
			if (tabbedPane.getSelectedComponent() == component) {
				tabChanged();
			}
			tabbedPane.setSelectedComponent(component);
		}
		return component != null;
	}

	/**
	 * Get the name of the current comparison panel being viewed
	 * 
	 * @return the tab name, or null if there is nothing selected
	 */
	public String getCurrentComponentName() {
		int selectedIndex = tabbedPane.getSelectedIndex();
		if (selectedIndex >= 0) {
			return tabbedPane.getTitleAt(selectedIndex);
		}
		return null;
	}

	/**
	 * Get the number of views in the tabbed pane
	 */
	int getNumberOfTabbedComponents() {
		return tabNameToComponentMap.size();
	}

	/**
	 * Remove all views in the tabbed pane 
	 */
	public void dispose() {
		tool.removeComponentProvider(provider);
		tabbedPane.removeAll();

		setVisible(false);
		for (CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel : codeComparisonPanels) {
			codeComparisonPanel.dispose();
		}
	}

	/**
	 * Create the main tabbed panel
	 */
	private void createMainPanel() {
		tabbedPane = new JTabbedPane();

		tabbedPane.addChangeListener(this);
		setLayout(new BorderLayout());

		add(tabbedPane, BorderLayout.CENTER);
		setPreferredSize(new Dimension(200, 300));

		for (CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel : codeComparisonPanels) {
			codeComparisonPanel.loadFunctions(leftComparisonData.getFunction(),
				rightComparisonData.getFunction());
			JComponent component = codeComparisonPanel.getComponent();
			tabbedPane.add(codeComparisonPanel.getTitle(), component);
			tabNameToComponentMap.put(codeComparisonPanel.getTitle(), component);
		}
	}

	/**
	 * Invoked when there is a tab change. This loads the active tab with
	 * the appropriate data to be compared.
	 */
	private void tabChanged() {
		CodeComparisonPanel<? extends FieldPanelCoordinator> activePanel =
			getActiveComparisonPanel();
		if (activePanel == null) {
			return; // initializing
		}

		if (leftComparisonData.isFunction() || rightComparisonData.isFunction()) {
			activePanel.loadFunctions(leftComparisonData.getFunction(),
				rightComparisonData.getFunction());
		}
		else if (leftComparisonData.isData() || rightComparisonData.isData()) {
			activePanel.loadData(leftComparisonData.getData(), rightComparisonData.getData());
		}
		else {
			activePanel.loadAddresses(leftComparisonData.getProgram(),
				rightComparisonData.getProgram(), leftComparisonData.getAddressSet(),
				rightComparisonData.getAddressSet());
		}
	}

	/**
	 * Returns the comparison panel that is in the selected tab
	 * 
	 * @return the currently selected comparison panel, or null if nothing
	 * selected
	 */
	private CodeComparisonPanel<? extends FieldPanelCoordinator> getActiveComparisonPanel() {
		JComponent c = (JComponent) tabbedPane.getSelectedComponent();
		for (CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel : codeComparisonPanels) {
			JComponent component = codeComparisonPanel.getComponent();
			if (c == component) {
				return codeComparisonPanel;
			}
		}

		return null;
	}

	/**
	 * Returns the comparison data object for the left panel
	 * 
	 * @return the comparison data object for the left panel
	 */
	public FunctionComparisonData getLeftComparisonData() {
		return leftComparisonData;
	}

	/**
	 * Returns the comparison data object for the right panel
	 * 
	 * @return the comparison data object for the right panel
	 */
	public FunctionComparisonData getRightComparisonData() {
		return rightComparisonData;
	}

	/**
	 * Gets the function currently displayed in the left side of this panel
	 * 
	 * @return the left function or null
	 */
	public Function getLeftFunction() {
		return leftComparisonData.getFunction();
	}

	/**
	 * Sets the function to display in the left side of this panel
	 * 
	 * @param function the function to display
	 */
	protected void setLeftFunction(Function function) {
		loadFunctions(function, rightComparisonData.getFunction());
	}

	/**
	 * Gets the function currently displayed in the right side of this panel
	 * 
	 * @return the right function or null
	 */
	public Function getRightFunction() {
		return rightComparisonData.getFunction();
	}

	/**
	 * Sets the function to display in the right side of this panel
	 * 
	 * @param function the function to display
	 */
	protected void setRightFunction(Function function) {
		loadFunctions(leftComparisonData.getFunction(), function);
	}

	/**
	 * Gets the data displayed in the left side of this panel
	 * 
	 * @return the left data or null
	 */
	public Data getLeftData() {
		return leftComparisonData.getData();
	}

	/**
	 * Gets the data displayed in the right side of this panel
	 * 
	 * @return the right data
	 */
	public Data getRightData() {
		return rightComparisonData.getData();
	}

	/**
	 * Enables/disables mouse navigation for all the CodeComparisonPanels 
	 * displayed by this panel
	 * 
	 * @param enabled true to enable mouse navigation in the panels
	 */
	public void setMouseNavigationEnabled(boolean enabled) {
		for (CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel : codeComparisonPanels) {
			codeComparisonPanel.setMouseNavigationEnabled(enabled);
		}
	}

	/**
	 * Sets up the FunctionComparisonPanel and which CodeComparisonPanel is currently 
	 * displayed based on the specified saveState
	 * 
	 * @param prefix identifier to prepend to any save state names to make them unique
	 * @param saveState the save state for retrieving information
	 */
	public void readConfigState(String prefix, SaveState saveState) {
		String currentTabView =
			saveState.getString(prefix + COMPARISON_VIEW_DISPLAYED, DEFAULT_CODE_COMPARISON_VIEW);
		setCurrentTabbedComponent(currentTabView);
		setScrollingSyncState(
			saveState.getBoolean(prefix + CODE_COMPARISON_LOCK_SCROLLING_TOGETHER, true));
		ListingCodeComparisonPanel dualListingPanel = getDualListingPanel();
		if (dualListingPanel != null) {
			dualListingPanel.readConfigState(prefix, saveState);
		}
	}

	/**
	 * Saves the information to the save state about the FunctionComparisonPanel and 
	 * which CodeComparisonPanel is currently displayed
	 * 
	 * @param prefix identifier to prepend to any save state names to make them unique
	 * @param saveState the save state where the information gets written
	 */
	public void writeConfigState(String prefix, SaveState saveState) {
		String currentComponentName = getCurrentComponentName();
		if (currentComponentName != null) {
			saveState.putString(prefix + COMPARISON_VIEW_DISPLAYED, getCurrentComponentName());
		}
		saveState.putBoolean(prefix + CODE_COMPARISON_LOCK_SCROLLING_TOGETHER, isScrollingSynced());
		ListingCodeComparisonPanel dualListingPanel = getDualListingPanel();
		if (dualListingPanel != null) {
			dualListingPanel.writeConfigState(prefix, saveState);
		}
	}

	/**
	 * Gets all actions for the FunctionComparisonPanel and all CodeComparisonPanels in this 
	 * FunctionComparisonPanel
	 * 
	 * @return the code comparison actions
	 */
	public DockingAction[] getCodeComparisonActions() {
		ArrayList<DockingAction> dockingActionList = new ArrayList<>();
		// Get actions for this functionComparisonPanel
		DockingAction[] functionComparisonActions = getActions();
		for (DockingAction dockingAction : functionComparisonActions) {
			dockingActionList.add(dockingAction);
		}
		// Get actions for each CodeComparisonPanel
		for (CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel : codeComparisonPanels) {
			DockingAction[] actions = codeComparisonPanel.getActions();
			for (DockingAction dockingAction : actions) {
				dockingActionList.add(dockingAction);
			}
		}
		return dockingActionList.toArray(new DockingAction[dockingActionList.size()]);
	}

	/**
	 * Sets the prefixes that are to be prepended to the title displayed for each side of 
	 * each CodeComparisonPanel
	 * 
	 * @param leftTitlePrefix the prefix to prepend to the left titles
	 * @param rightTitlePrefix the prefix to prepend to the right titles
	 */
	public void setTitlePrefixes(String leftTitlePrefix, String rightTitlePrefix) {
		Component[] components = tabbedPane.getComponents();
		for (Component component : components) {
			if (component instanceof CodeComparisonPanel<?>) {
				((CodeComparisonPanel<?>) component).setTitlePrefixes(leftTitlePrefix,
					rightTitlePrefix);
			}
		}
	}

	/**
	 * Returns the action context for a given mouse event and provider
	 * 
	 * @param event the mouse event
	 * @param componentProvider the component provider
	 * @return the action context
	 */
	public ActionContext getActionContext(MouseEvent event, ComponentProvider componentProvider) {
		Object source = (event != null) ? event.getSource() : null;
		Component sourceComponent = (source instanceof Component) ? (Component) source : null;
		ListingCodeComparisonPanel dualListingPanel = getDualListingPanel();
		// Is the action being taken on the dual listing.
		if (dualListingPanel != null && dualListingPanel.isAncestorOf(sourceComponent)) {
			return dualListingPanel.getActionContext(event, componentProvider);
		}
		return null;
	}

	/**
	 * Determines if the layouts of the views are synchronized with respect 
	 * to scrolling and location
	 * 
	 * @return true if scrolling is synchronized between the two views
	 */
	public final boolean isScrollingSynced() {
		return syncScrolling;
	}

	/**
	 * Sets whether or not scrolling is synchronized
	 * 
	 * @param syncScrolling true means synchronize scrolling and location 
	 * between the two views
	 */
	public void setScrollingSyncState(boolean syncScrolling) {
		if (isScrollingSynced() == syncScrolling) {
			return;
		}
		toggleScrollLockAction.setSelected(syncScrolling);
		toggleScrollLockAction.setToolBarData(new ToolBarData(
			syncScrolling ? SYNC_SCROLLING_ICON : UNSYNC_SCROLLING_ICON, SCROLLING_GROUP));
		// Notify each comparison panel of the scrolling sync state.
		for (CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel : codeComparisonPanels) {
			codeComparisonPanel.setScrollingSyncState(syncScrolling);
		}
		this.syncScrolling = syncScrolling;
	}

	/**
	 * Gets the currently displayed CodeComparisonPanel
	 * 
	 * @return the current panel or null.
	 */
	public CodeComparisonPanel<? extends FieldPanelCoordinator> getDisplayedPanel() {
		int selectedIndex = tabbedPane.getSelectedIndex();
		Component component = tabbedPane.getComponentAt(selectedIndex);
		return (CodeComparisonPanel<?>) component;
	}

	/**
	 * Updates the enablement for all actions provided by each panel
	 */
	public void updateActionEnablement() {
		for (CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel : codeComparisonPanels) {
			codeComparisonPanel.updateActionEnablement();
		}
	}

	/**
	* Get the current code comparison panel being viewed
	* 
	* @return null if there is no code comparison panel
	*/
	CodeComparisonPanel<? extends FieldPanelCoordinator> getCurrentComponent() {
		return (CodeComparisonPanel<?>) tabbedPane.getSelectedComponent();
	}

	/**
	 * Returns true if the clicked object is a tab
	 * 
	 * @param event the mouse event
	 * @return true if the clicked object is a tab
	 */
	boolean isTabClick(MouseEvent event) {
		Component component = event.getComponent();
		int tabCount = tabbedPane.getTabCount();
		for (int i = 0; i < tabCount; i++) {
			DockingTabRenderer renderer = (DockingTabRenderer) tabbedPane.getTabComponentAt(i);
			if (SwingUtilities.isDescendingFrom(component, renderer)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Creates the actions available for this panel
	 */
	private void createActions() {
		toggleScrollLockAction = new ToggleScrollLockAction();
	}

	/**
	 * Action that sets the scrolling state of the comparison panels
	 */
	private class ToggleScrollLockAction extends ToggleDockingAction {
		ToggleScrollLockAction() {
			super("Synchronize Scrolling of Dual View", provider.getName());
			setDescription("Lock/Unlock Synchronized Scrolling of Dual View");
			setToolBarData(new ToolBarData(UNSYNC_SCROLLING_ICON, SCROLLING_GROUP));
			setEnabled(true);
			MenuData menuData =
				new MenuData(new String[] { "Synchronize Scrolling" }, DUAL_SCROLLING_ACTION_GROUP);
			setMenuBarData(menuData);

			setHelpLocation(
				new HelpLocation(DUAL_SCROLLING_HELP_TOPIC, "Synchronize Scrolling of Dual View"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			setScrollingSyncState(isSelected());
		}
	}

	public List<CodeComparisonPanel<? extends FieldPanelCoordinator>> getComparisonPanels() {
		return codeComparisonPanels;
	}

	/**
	 * Discovers the CodeComparisonPanels which are extension points
	 * 
	 * @return the CodeComparisonPanels which are extension points
	 */
	private List<CodeComparisonPanel<? extends FieldPanelCoordinator>> getCodeComparisonPanels() {
		if (codeComparisonPanels == null) {
			codeComparisonPanels = new ArrayList<>();
			Set<CodeComparisonPanel<? extends FieldPanelCoordinator>> instances =
				createAllPossibleCodeComparisonPanels();

			// Put all panels in CodeComparisonPanel list; at same time, get a 
			// list of superseded panels.
			ArrayList<Class<? extends CodeComparisonPanel<? extends FieldPanelCoordinator>>> classesOfPanelsToSupersede =
				new ArrayList<>();
			for (CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel : instances) {
				codeComparisonPanels.add(codeComparisonPanel);
				Class<? extends CodeComparisonPanel<? extends FieldPanelCoordinator>> panelThisSupersedes =
					codeComparisonPanel.getPanelThisSupersedes();
				if (panelThisSupersedes != null) {
					classesOfPanelsToSupersede.add(panelThisSupersedes);
				}
			}

			// Now go back through the panels and remove those that another one wants to supersede.
			Iterator<CodeComparisonPanel<? extends FieldPanelCoordinator>> iterator =
				codeComparisonPanels.iterator();
			while (iterator.hasNext()) {
				CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel =
					iterator.next();
				if (classesOfPanelsToSupersede.contains(codeComparisonPanel.getClass())) {
					// Remove the superseded panel.
					iterator.remove();
				}
			}

			codeComparisonPanels.sort((p1, p2) -> p1.getTitle().compareTo(p2.getTitle()));
		}
		return codeComparisonPanels;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private Set<CodeComparisonPanel<? extends FieldPanelCoordinator>> createAllPossibleCodeComparisonPanels() {
		Set<CodeComparisonPanel<? extends FieldPanelCoordinator>> instances = new HashSet<>();
		List<Class<? extends CodeComparisonPanel>> classes =
			ClassSearcher.getClasses(CodeComparisonPanel.class);
		for (Class<? extends CodeComparisonPanel> panelClass : classes) {
			try {
				Constructor<? extends CodeComparisonPanel> constructor =
					panelClass.getConstructor(String.class, PluginTool.class);
				CodeComparisonPanel panel = constructor.newInstance(provider.getName(), tool);
				instances.add(panel);
			}
			catch (NoSuchMethodException | SecurityException | InstantiationException
					| IllegalAccessException | IllegalArgumentException
					| InvocationTargetException e) {
				Msg.showError(this, null, "Error Creating Extension Point",
					"Error creating class " + panelClass.getName() +
						" when creating extension points for " +
						CodeComparisonPanel.class.getName(),
					e);
			}
		}
		return instances;
	}
}
