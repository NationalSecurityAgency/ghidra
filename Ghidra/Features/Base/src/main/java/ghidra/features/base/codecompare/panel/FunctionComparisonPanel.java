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
package ghidra.features.base.codecompare.panel;

import static ghidra.features.base.codecompare.panel.ComparisonData.*;
import static ghidra.util.datastruct.Duo.Side.*;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.lang.reflect.Constructor;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.*;
import docking.widgets.tabbedpane.DockingTabRenderer;
import generic.theme.GIcon;
import ghidra.features.base.codecompare.listing.ListingCodeComparisonView;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.datastruct.Duo;
import help.Help;
import help.HelpService;

/**
 * A panel for displaying {@link Function functions} side-by-side for comparison purposes
 */
public class FunctionComparisonPanel extends JPanel implements ChangeListener {
	private static final String ORIENTATION_PROPERTY_NAME = "ORIENTATION";

	private static final String DEFAULT_CODE_COMPARISON_VIEW = ListingCodeComparisonView.NAME;
	private static final String COMPARISON_VIEW_DISPLAYED = "COMPARISON_VIEW_DISPLAYED";
	private static final String CODE_COMPARISON_LOCK_SCROLLING_TOGETHER =
		"CODE_COMPARISON_LOCK_SCROLLING_TOGETHER";

	private static final String HELP_TOPIC = "FunctionComparison";

	private static final Icon SYNC_SCROLLING_ICON =
		new GIcon("icon.plugin.functioncompare.scroll.lock");
	private static final Icon UNSYNC_SCROLLING_ICON =
		new GIcon("icon.plugin.functioncompare.scroll.unlock");
	private static final String SCROLLING_GROUP = "A9_SCROLLING";
	private static final String DUAL_SCROLLING_ACTION_GROUP = "DualScrolling";
	private static final String DUAL_SCROLLING_HELP_TOPIC = "FunctionComparison";

	private JTabbedPane tabbedPane;
	private Map<String, JComponent> tabNameToComponentMap;
	private List<CodeComparisonView> codeComparisonViews;
	private ToggleScrollLockAction toggleScrollLockAction;
	private boolean syncScrolling = false;

	private Duo<ComparisonData> comparisonData = new Duo<ComparisonData>();

	private FunctionComparisonState state;

	/**
	 * Constructor 
	 * @param tool the tool
	 * @param owner the owner's name
	 * @param state the comparison save state
	 */
	public FunctionComparisonPanel(PluginTool tool, String owner, FunctionComparisonState state) {
		this.comparisonData = new Duo<>(EMPTY, EMPTY);
		this.state = state;

		state.addUpdateCallback(this::comparisonStateUpdated);

		codeComparisonViews = getCodeComparisonViews(tool, owner);
		tabNameToComponentMap = new HashMap<>();
		createMainPanel();
		createActions(owner);
		setScrollingSyncState(true);
		HelpService help = Help.getHelpService();
		help.registerHelp(this, new HelpLocation(HELP_TOPIC, "Function Comparison"));
	}

	private void comparisonStateUpdated() {
		readPanelState();
		readViewState();
	}

	/**
	 * Load the given functions into the views of this panel
	 *
	 * @param leftFunction The function for the left side of the panel
	 * @param rightFunction The function for the right side of the panel
	 */
	public void loadFunctions(Function leftFunction, Function rightFunction) {
		ComparisonData left =
			leftFunction == null ? EMPTY : new FunctionComparisonData(leftFunction);
		ComparisonData right =
			rightFunction == null ? EMPTY : new FunctionComparisonData(rightFunction);
		loadComparisons(left, right);
	}

	/**
	 * Load the given data into the views of this panel
	 *
	 * @param leftData The data for the left side of the panel
	 * @param rightData The data for the right side of the panel
	 */
	public void loadData(Data leftData, Data rightData) {
		ComparisonData left = new DataComparisonData(leftData, rightData.getLength());
		ComparisonData right = new DataComparisonData(rightData, leftData.getLength());
		loadComparisons(left, right);
	}

	public void loadComparisons(ComparisonData left, ComparisonData right) {
		comparisonData = new Duo<>(left, right);

		CodeComparisonView activeView = getActiveComparisonView();
		if (activeView != null) {
			activeView.loadComparisons(left, right);
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
		ComparisonData left = new AddressSetComparisonData(leftProgram, leftAddresses);
		ComparisonData right = new AddressSetComparisonData(rightProgram, rightAddresses);
		loadComparisons(left, right);
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
		String leftShort = comparisonData.get(LEFT).getShortDescription();
		String rightShort = comparisonData.get(LEFT).getShortDescription();

		return leftShort + " & " + rightShort;
	}

	/**
	 * Clear both sides of this panel
	 */
	public void clear() {
		comparisonData = new Duo<>(EMPTY, EMPTY);

		// Setting the addresses to be displayed to null effectively clears
		// the display
		CodeComparisonView activeView = getActiveComparisonView();
		if (activeView != null) {
			activeView.clearComparisons();
		}
	}

	/**
	 * Returns true if the comparison window has no information to display in
	 * either the left or right panel
	 *
	 * @return true if the comparison window has no information to display
	 */
	public boolean isEmpty() {
		return comparisonData.get(LEFT).isEmpty() || comparisonData.get(RIGHT).isEmpty();
	}

	/**
	 * Gets the ListingCodeComparisonView being displayed by this panel
	 * if one exists
	 *
	 * @return the comparison panel or null
	 */
	public ListingCodeComparisonView getDualListingView() {
		for (CodeComparisonView view : codeComparisonViews) {
			if (view instanceof ListingCodeComparisonView listingView) {
				return listingView;
			}
		}
		return null;
	}

	@Override
	public void stateChanged(ChangeEvent e) {
		tabChanged();
		writeTabState();
	}

	/**
	 * Set the current tabbed panel to be the component with the given name
	 *
	 * @param name name of view to set as the current tab
	 * @return true if the named view was found in the view map
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
	 * @return the number of views in the tabbed pane
	 */
	int getNumberOfTabbedComponents() {
		return tabNameToComponentMap.size();
	}

	/**
	 * Remove all views in the tabbed pane
	 */
	public void dispose() {
		tabbedPane.removeAll();

		setVisible(false);
		for (CodeComparisonView view : codeComparisonViews) {
			view.dispose();
		}
	}

	public void programClosed(Program program) {
		for (CodeComparisonView view : codeComparisonViews) {
			view.programClosed(program);
		}
	}

	public CodeComparisonView getCodeComparisonView(String name) {
		for (CodeComparisonView view : codeComparisonViews) {
			if (name.equals(view.getName())) {
				return view;
			}
		}
		return null;
	}

	public void selectComparisonView(String name) {
		for (CodeComparisonView view : codeComparisonViews) {
			if (name.equals(view.getName())) {
				tabbedPane.setSelectedComponent(view);
			}
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

		for (CodeComparisonView view : codeComparisonViews) {
			tabbedPane.add(view.getName(), view);
			tabNameToComponentMap.put(view.getName(), view);
		}
	}

	/**
	 * Invoked when there is a tab change. This loads the active tab with the data to be compared.
	 */
	private void tabChanged() {
		CodeComparisonView activeView = getActiveComparisonView();
		if (activeView == null) {
			return; // initializing
		}
		activeView.loadComparisons(comparisonData.get(LEFT), comparisonData.get(RIGHT));
	}

	/**
	 * Returns the comparison panel that is in the selected tab
	 *
	 * @return the currently selected comparison panel, or null if nothing
	 * selected
	 */
	private CodeComparisonView getActiveComparisonView() {
		return (CodeComparisonView) tabbedPane.getSelectedComponent();
	}

	private void readViewState() {
		CodeComparisonViewState viewState = state.getViewState();
		codeComparisonViews.forEach(v -> {
			Class<? extends CodeComparisonView> viewClass = v.getClass();
			SaveState saveState = viewState.getSaveState(viewClass);
			v.setSaveState(saveState);
		});
	}

	private void readPanelState() {

		SaveState panelState = state.getPanelState();
		String currentTabView =
			panelState.getString(COMPARISON_VIEW_DISPLAYED, DEFAULT_CODE_COMPARISON_VIEW);
		setCurrentTabbedComponent(currentTabView);
		setScrollingSyncState(
			panelState.getBoolean(CODE_COMPARISON_LOCK_SCROLLING_TOGETHER, true));

		for (CodeComparisonView view : codeComparisonViews) {
			String key = view.getName() + ORIENTATION_PROPERTY_NAME;
			view.setSideBySide(panelState.getBoolean(key, true));
		}
	}

	private void writeTabState() {
		String currentComponentName = getCurrentComponentName();
		if (currentComponentName == null) {
			return;
		}

		SaveState panelState = state.getPanelState();
		panelState.putString(COMPARISON_VIEW_DISPLAYED, getCurrentComponentName());
		state.setChanged();
	}

	private void writeScrollState() {
		SaveState panelState = state.getPanelState();
		panelState.putBoolean(CODE_COMPARISON_LOCK_SCROLLING_TOGETHER, isScrollingSynced());
		state.setChanged();
	}

	private void writeOrientationState() {

		SaveState panelState = state.getPanelState();
		for (CodeComparisonView view : codeComparisonViews) {
			String key = view.getName() + ORIENTATION_PROPERTY_NAME;
			boolean sideBySide = view.isSideBySide();
			panelState.putBoolean(key, sideBySide);
		}
	}

	public DockingAction[] getCodeComparisonActions() {
		ArrayList<DockingAction> dockingActionList = new ArrayList<>();

		// Get actions for this panel
		DockingAction[] actions = getActions();
		for (DockingAction action : actions) {
			dockingActionList.add(action);
		}

		// Get actions for each view
		for (CodeComparisonView view : codeComparisonViews) {
			dockingActionList.addAll(view.getActions());
		}

		return dockingActionList.toArray(new DockingAction[dockingActionList.size()]);
	}

	/**
	 * Sets the prefixes that are to be prepended to the title displayed for each side of
	 * each {@link CodeComparisonView}
	 *
	 * @param leftTitlePrefix the prefix to prepend to the left titles
	 * @param rightTitlePrefix the prefix to prepend to the right titles
	 */
	public void setTitlePrefixes(String leftTitlePrefix, String rightTitlePrefix) {
		Component[] components = tabbedPane.getComponents();
		for (Component component : components) {
			if (component instanceof CodeComparisonView) {
				((CodeComparisonView) component).setTitlePrefixes(leftTitlePrefix,
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
		CodeComparisonView activeProvider = getDisplayedView();
		if (activeProvider != null) {
			return activeProvider.getActionContext(componentProvider, event);
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
		for (CodeComparisonView view : codeComparisonViews) {
			view.setSynchronizedScrolling(syncScrolling);
		}
		this.syncScrolling = syncScrolling;

		writeScrollState();
	}

	/**
	 * Gets the currently displayed {@link CodeComparisonView}
	 *
	 * @return the current panel or null.
	 */
	public CodeComparisonView getDisplayedView() {
		int selectedIndex = tabbedPane.getSelectedIndex();
		Component component = tabbedPane.getComponentAt(selectedIndex);
		return (CodeComparisonView) component;
	}

	/**
	 * Updates the enablement for all actions provided by each view
	 */
	public void updateActionEnablement() {
		for (CodeComparisonView view : codeComparisonViews) {
			view.updateActionEnablement();
		}
	}

	/**
	* Get the current code comparison view being viewed
	*
	* @return null if there is no code comparison view
	*/
	public CodeComparisonView getCurrentView() {
		return (CodeComparisonView) tabbedPane.getSelectedComponent();
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
	private void createActions(String owner) {
		toggleScrollLockAction = new ToggleScrollLockAction(owner);
	}

	/**
	 * Action that sets the scrolling state of the comparison panels
	 */
	private class ToggleScrollLockAction extends ToggleDockingAction {
		ToggleScrollLockAction(String owner) {
			super("Synchronize Scrolling of Dual View", owner);
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

	public List<CodeComparisonView> getComparisonView() {
		return codeComparisonViews;
	}

	/**
	 * Discovers the {@link CodeComparisonView}s which are extension points
	 *
	 * @return the views which are extension points
	 */
	private List<CodeComparisonView> getCodeComparisonViews(PluginTool tool, String owner) {
		if (codeComparisonViews == null) {
			codeComparisonViews = createAllCodeComparisonViews(tool, owner);
			codeComparisonViews.sort((p1, p2) -> p1.getName().compareTo(p2.getName()));
		}
		return codeComparisonViews;
	}

	private List<CodeComparisonView> createAllCodeComparisonViews(PluginTool tool,
			String owner) {

		CodeComparisonViewState viewState = state.getViewState();
		List<CodeComparisonView> instances = new ArrayList<>();
		List<Class<? extends CodeComparisonView>> classes =
			ClassSearcher.getClasses(CodeComparisonView.class);
		for (Class<? extends CodeComparisonView> viewClass : classes) {
			try {
				Constructor<? extends CodeComparisonView> constructor =
					viewClass.getConstructor(String.class, PluginTool.class);
				CodeComparisonView view = constructor.newInstance(owner, tool);

				SaveState saveState = viewState.getSaveState(viewClass);
				view.setSaveState(saveState);

				view.setOrientationChangedCallback(() -> writeOrientationState());

				instances.add(view);
			}
			catch (Exception e) {
				Msg.showError(this, null, "Error Creating Extension Point",
					"Error creating class " + viewClass.getName() +
						" when creating extension points for " +
						CodeComparisonView.class.getName(),
					e);
			}
		}
		return instances;
	}
}
