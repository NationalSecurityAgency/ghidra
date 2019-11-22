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
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import resources.ResourceManager;

/**
 * A panel for displaying two functions side by side for comparison purposes.<br>
 * This panel is intended to discover and provide multiple different types of
 * CodeComparisonPanels. Each type of {@link CodeComparisonPanel} will be in its own tab. 
 * The user can only view one type of CodeComparisonPanel at a time, but can select the 
 * currently displayed one.
 * 
 */
public class FunctionComparisonPanel extends JPanel implements ChangeListener {

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
	private HashMap<String, JComponent> tabNameToComponentMap;
	protected PluginTool tool;
	protected ComponentProvider provider;
	protected Program leftProgram;
	protected Program rightProgram;
	private Function leftFunction;
	private Function rightFunction;
	private Data leftData;
	private Data rightData;
	private AddressSetView leftAddressSet = new AddressSet();
	private AddressSetView rightAddressSet = new AddressSet();
	private List<CodeComparisonPanel<? extends FieldPanelCoordinator>> codeComparisonPanels;
	private ToggleScrollLockAction toggleScrollLockAction;
	private boolean syncScrolling = false;

	/**
	 * Creates a panel for comparing two functions.
	 * @param provider the GUI provider that includes this panel.
	 * @param tool the tool containing this panel
	 * @param leftFunction the function displayed in the left side of the panel.
	 * @param rightFunction the function displayed in the right side of the panel.
	 */
	public FunctionComparisonPanel(ComponentProvider provider, PluginTool tool,
			Function leftFunction, Function rightFunction) {
		this.provider = provider;
		this.tool = tool;
		this.leftFunction = leftFunction;
		this.rightFunction = rightFunction;
		leftProgram = (leftFunction != null) ? leftFunction.getProgram() : null;
		rightProgram = (rightFunction != null) ? rightFunction.getProgram() : null;
		this.codeComparisonPanels = getCodeComparisonPanels();
		this.leftAddressSet = (leftFunction != null) ? leftFunction.getBody() : new AddressSet();
		this.rightAddressSet = (rightFunction != null) ? rightFunction.getBody() : new AddressSet();
		tabNameToComponentMap = new HashMap<>();
		create();
		createActions();
		setScrollingSyncState(true);
		help.registerHelp(this, new HelpLocation(HELP_TOPIC, "Function Comparison"));
	}

	// Discovers the CodeComparisonPanels which are extension points.
	private List<CodeComparisonPanel<? extends FieldPanelCoordinator>> getCodeComparisonPanels() {
		if (codeComparisonPanels == null) {
			codeComparisonPanels = new ArrayList<>();
			Set<CodeComparisonPanel<? extends FieldPanelCoordinator>> instances =
				createAllPossibleCodeComparisonPanels();

			// Put all panels in CodeComparisonPanel list.
			// At same time, get a list of superseded panels.
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

			// Sort the list of code comparison panels so they display in the same order
			// each time for the user.
			CodeComparisonPanelComparator comparator = new CodeComparisonPanelComparator();
			codeComparisonPanels.sort(comparator);
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

	/**
	 * Load the given functions into the views of this panel.
	 * 
	 * @param newLeftFunction The function for the left side of the panel
	 * @param newRightFunction The function for the right side of the panel
	 */
	public void loadFunctions(Function newLeftFunction, Function newRightFunction) {
		if (leftFunction != null && leftFunction.equals(newLeftFunction) && rightFunction != null &&
			rightFunction.equals(newRightFunction)) {
			return; // already showing
		}

		leftData = null;
		rightData = null;
		leftFunction = newLeftFunction;
		rightFunction = newRightFunction;
		leftProgram = (leftFunction != null) ? leftFunction.getProgram() : null;
		rightProgram = (rightFunction != null) ? rightFunction.getProgram() : null;
		leftAddressSet = (leftFunction != null) ? leftFunction.getBody() : new AddressSet();
		rightAddressSet = (rightFunction != null) ? rightFunction.getBody() : new AddressSet();

		CodeComparisonPanel<? extends FieldPanelCoordinator> activePanel =
			getActiveComparisonPanel();
		if (activePanel != null) {
			activePanel.loadFunctions(leftFunction, rightFunction);
		}
	}

	/**
	 * Load the given data into the views of this panel.
	 * 
	 * @param newLeftData The data for the left side of the panel
	 * @param newRightData The data for the right side of the panel
	 */
	public void loadData(Data newLeftData, Data newRightData) {
		if (leftData != null && leftData.equals(newLeftData) && rightData != null &&
			rightData.equals(newRightData)) {
			return; // already showing
		}

		this.leftFunction = null;
		this.rightFunction = null;
		this.leftData = newLeftData;
		this.rightData = newRightData;
		leftProgram = (leftData != null) ? leftData.getProgram() : null;
		rightProgram = (rightData != null) ? rightData.getProgram() : null;

		leftAddressSet =
			(leftData != null) ? new AddressSet(leftData.getMinAddress(), leftData.getMaxAddress())
					: new AddressSet();
		rightAddressSet = (rightData != null)
				? new AddressSet(rightData.getMinAddress(), rightData.getMaxAddress())
				: new AddressSet();

		CodeComparisonPanel<? extends FieldPanelCoordinator> activePanel =
			getActiveComparisonPanel();
		if (activePanel != null) {
			activePanel.loadData(leftData, rightData);
		}
	}

	/**
	 * Load info for the the given addresses of the indicated programs into the views of this panel.
	 * 
	 * @param newLeftProgram the program for the left side of the panel
	 * @param newRightProgram the program for the right side of the panel
	 * @param newLeftAddresses addresses for the info to display in the left side of the panel
	 * @param newRightAddresses addresses for the info to display in the right side of the panel
	 */
	public void loadAddresses(Program newLeftProgram, Program newRightProgram,
			AddressSetView newLeftAddresses, AddressSetView newRightAddresses) {
		leftData = null;
		rightData = null;
		leftFunction = null;
		rightFunction = null;

		leftProgram = newLeftProgram;
		rightProgram = newRightProgram;
		leftAddressSet = new AddressSet(newLeftAddresses); // AddressSet constructor handles null.
		rightAddressSet = new AddressSet(newRightAddresses); // AddressSet constructor handles null.
		CodeComparisonPanel<? extends FieldPanelCoordinator> activePanel =
			getActiveComparisonPanel();
		if (activePanel != null) {
			activePanel.loadAddresses(leftProgram, rightProgram, leftAddressSet, rightAddressSet);
		}
	}

	/**
	 * clear both sides of this panel.
	 */
	public void clear() {
		leftData = null;
		rightData = null;
		leftFunction = null;
		rightFunction = null;

		leftAddressSet = new AddressSet(); // AddressSet constructor handles null.
		rightAddressSet = new AddressSet(); // AddressSet constructor handles null.
		CodeComparisonPanel<? extends FieldPanelCoordinator> activePanel =
			getActiveComparisonPanel();
		if (activePanel != null) {
			activePanel.loadAddresses(null, null, null, null);
		}
	}

	/**
	 * Gets the ListingCodeComparisonPanel being displayed by this panel if one exists.
	 * @return the ListingCodeComparisonPanel or null
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

	/**
	 * Invoked when the target of the listener has changed its state. In
	 * this case, the method is called when the user switches to another
	 * tab in the tabbed pane.
	 *
	 * @param e  a ChangeEvent object
	 */
	@Override
	public void stateChanged(ChangeEvent e) {
		tabChanged();
	}

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
	 * Set the current tabbed panel to be the component with the given name.
	 * @param name name of view to be current ( for example the "Listing View" )
	 * @return true if the named view was found in the provider map
	 */
	public boolean setCurrentTabbedComponent(String name) {

		JComponent component = tabNameToComponentMap.get(name);
		if (component != null) {
			if (tabbedPane.getSelectedComponent() == component) {
				tabChanged();
			}
			tabbedPane.setSelectedComponent(component); // causes a state change event
		}
		return component != null;
	}

	/**
	 * Get the current code comparison panel being viewed.
	 * 
	 * @return null if there is no code comparison panel.
	 */
	CodeComparisonPanel<? extends FieldPanelCoordinator> getCurrentComponent() {
		return (CodeComparisonPanel<?>) tabbedPane.getSelectedComponent();
	}

	/**
	 * Get the name for the current code comparison panel being viewed.
	 * 
	 * @return null if there is no code comparison panel.
	 */
	public String getCurrentComponentName() {
		int selectedIndex = tabbedPane.getSelectedIndex();
		if (selectedIndex >= 0) {
			return tabbedPane.getTitleAt(selectedIndex);
		}
		return null;
	}

	/**
	 * Get the number of views in the tabbed pane.
	 */
	int getNumberOfTabbedComponents() {
		return tabNameToComponentMap.size();
	}

	/**
	 * Remove all views in the tabbed pane. 
	 */
	public void dispose() {
		tool.removeComponentProvider(provider);
		tabbedPane.removeAll();

		setVisible(false);
		for (CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel : codeComparisonPanels) {
			codeComparisonPanel.dispose();
		}
	}

	/////////////////////////////////////////////////////////////////////////
	// ** private methods **
	/////////////////////////////////////////////////////////////////////////
	/**
	 * Create the tabbed pane.
	 */
	private void create() {
		tabbedPane = new JTabbedPane();

		tabbedPane.addChangeListener(this);
		setLayout(new BorderLayout());

		add(tabbedPane, BorderLayout.CENTER);
		setPreferredSize(new Dimension(200, 300));

		leftProgram = (leftFunction != null) ? leftFunction.getProgram() : null;
		rightProgram = (rightFunction != null) ? rightFunction.getProgram() : null;

		for (CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel : codeComparisonPanels) {
			codeComparisonPanel.loadFunctions(leftFunction, rightFunction);
			JComponent component = codeComparisonPanel.getComponent();
			addTab(codeComparisonPanel.getTitle(), component);
		}
	}

	private void addTab(String title, JComponent component) {
		tabbedPane.add(title, component);
		tabNameToComponentMap.put(title, component);
	}

	/**
	 * If the panel is active, then set the current tab to be active
	 * and all others to be inactive.
	 */
	private void tabChanged() {
		CodeComparisonPanel<? extends FieldPanelCoordinator> activePanel =
			getActiveComparisonPanel();
		if (activePanel == null) {
			return; // initializing
		}

		if (leftFunction != null || rightFunction != null) {
			activePanel.loadFunctions(leftFunction, rightFunction);
		}
		else if (leftData != null || rightData != null) {
			activePanel.loadData(leftData, rightData);
		}
		else {
			activePanel.loadAddresses(leftProgram, rightProgram, leftAddressSet, rightAddressSet);
		}
	}

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
	 * Gets the functions currently displayed by this panel. The first function in the array is the 
	 * left function and the second function is the right function. The value for the left or right
	 * function can be null.
	 * @return the functions displayed.
	 */
	public Function[] getFunctions() {
		return new Function[] { leftFunction, rightFunction };
	}

	/**
	 * Gets the function currently displayed in the left side of this panel or null if no function 
	 * is currently displayed.
	 * @return the left function or null
	 */
	public Function getLeftFunction() {
		return leftFunction;
	}

	/**
	 * Sets the function to display in the left side of this panel.
	 * @param function the function to display or null to clear the left side.
	 */
	protected void setLeftFunction(Function function) {
		loadFunctions(function, rightFunction);
	}

	/**
	 * Gets the function currently displayed in the right side of this panel or null if no function 
	 * is currently displayed.
	 * @return the right function or null
	 */
	public Function getRightFunction() {
		return rightFunction;
	}

	/**
	 * Sets the function to display in the right side of this panel.
	 * @param function the function to display or null to clear the right side.
	 */
	protected void setRightFunction(Function function) {
		loadFunctions(leftFunction, function);
	}

	/**
	 * Gets the data displayed in the left side of this panel.
	 * @return the left data or null
	 */
	public Data getLeftData() {
		return leftData;
	}

	/**
	 * Gets the data displayed in the right side of this panel.
	 * @return the right data or null
	 */
	public Data getRightData() {
		return rightData;
	}

	/**
	 * Enables/disables mouse navigation for all the CodeComparisonPanels displayed by this panel.
	 * @param enabled true means to enable mouse navigation in the panels.
	 */
	public void setMouseNavigationEnabled(boolean enabled) {
		for (CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel : codeComparisonPanels) {
			codeComparisonPanel.setMouseNavigationEnabled(enabled);
		}
	}

	/**
	 * Sets up the FunctionComparisonPanel and which CodeComparisonPanel is currently 
	 * displayed based on the specified saveState.
	 * @param prefix identifier to prepend to any save state names to make them unique.
	 * @param saveState the save state for retrieving information.
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
	 * which CodeComparisonPanel is currently displayed.
	 * @param prefix identifier to prepend to any save state names to make them unique.
	 * @param saveState the save state where the information gets written.
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
	 * FunctionComparisonPanel.
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
	 * Comparator that lets CodeComparisonPanels be sorted based on their title names.
	 */
	private class CodeComparisonPanelComparator
			implements Comparator<CodeComparisonPanel<? extends FieldPanelCoordinator>> {

		private CodeComparisonPanelComparator() {

		}

		@Override
		public int compare(CodeComparisonPanel<? extends FieldPanelCoordinator> o1,
				CodeComparisonPanel<? extends FieldPanelCoordinator> o2) {
			if (o1 == o2) {
				return 0;
			}
			String title1 = o1.getTitle();
			String title2 = o2.getTitle();
			return title1.compareTo(title2);
		}
	}

	/**
	 * Gets the currently displayed CodeComparisonPanel.
	 * @return the current panel or null.
	 */
	public CodeComparisonPanel<? extends FieldPanelCoordinator> getDisplayedPanel() {
		int selectedIndex = tabbedPane.getSelectedIndex();
		Component component = tabbedPane.getComponentAt(selectedIndex);
		return (CodeComparisonPanel<?>) component;
	}

	/**
	 * Gets all CodeComparisonPanels that are part of this FunctionComparisonPanel that match
	 * the indicated class.
	 * @param clazz the class of CodeComparisonPanels to return.
	 * @return the panels that match the specified class.
	 */
	public List<CodeComparisonPanel<? extends FieldPanelCoordinator>> getMatchingPanels(
			Class<? extends CodeComparisonPanel<? extends FieldPanelCoordinator>> clazz) {
		ArrayList<CodeComparisonPanel<? extends FieldPanelCoordinator>> matchingPanels =
			new ArrayList<>();
		Component[] components = tabbedPane.getComponents();
		for (Component component : components) {
			if (clazz.isAssignableFrom(component.getClass())) {
				matchingPanels.add((CodeComparisonPanel<?>) component);
			}
		}
		return matchingPanels;
	}

	/**
	 * Sets the prefixes that are to be prepended to the title displayed for each side of 
	 * each CodeComparisonPanel.
	 * @param leftTitlePrefix the prefix to prepend to the left titles.
	 * @param rightTitlePrefix the prefix to prepend to the right titles.
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
	 * Determines if the layouts of the views are synchronized with respect to scrolling and
	 * location.
	 * @return true if scrolling is synchronized between the two views.
	 */
	public final boolean isScrollingSynced() {
		return syncScrolling;
	}

	/**
	 * Sets whether or not scrolling is synchronized.
	 * @param syncScrolling true means synchronize scrolling and location between the two views.
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

	private void createActions() {
		toggleScrollLockAction = new ToggleScrollLockAction();
	}

	/**
	 * Get the actions for this FunctionComparisonPanel.
	 * @return an array containing the actions
	 */
	public DockingAction[] getActions() {
		DockingAction[] actions = new DockingAction[] { toggleScrollLockAction };
		return actions;
	}

	/**
	 * Updates the enablement for all actions provided by each panel.
	 */
	public void updateActionEnablement() {
		for (CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel : codeComparisonPanels) {
			codeComparisonPanel.updateActionEnablement();
		}
	}

	class ToggleScrollLockAction extends ToggleDockingAction {
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
}
