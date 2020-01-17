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
package ghidra.app.util.viewer.util;

import java.awt.Color;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.border.Border;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.internal.FieldPanelCoordinator;
import ghidra.app.plugin.core.functioncompare.FunctionComparisonPanel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * The CodeComparisonPanel class should be extended by any class that is to be 
 * discovered by the {@link FunctionComparisonPanel} class and included as a 
 * form of comparing two sections of code within the same or different programs
 * <p>
 * NOTE: ALL CodeComparisonPanel CLASSES MUST END IN
 * <code>CodeComparisonPanel</code> so they are discoverable by the 
 * {@link ClassSearcher} 
 */
public abstract class CodeComparisonPanel<T extends FieldPanelCoordinator> extends JPanel
		implements ExtensionPoint, FocusListener {

	// MINIMUM_PANEL_WIDTH is used to establish a minimum panel width for the left or right panel. 
	// Without it a long title in either panel can cause the split pane's divider to become locked.
	protected static final int MINIMUM_PANEL_WIDTH = 50;

	protected static final int LEFT = 0;
	protected static final int RIGHT = 1;
	private static final Color BUBBLE_GUM_PINK_COLOR = new Color(0xff, 0xa5, 0xa5);
	protected static final Border FOCUS_BORDER =
		BorderFactory.createMatteBorder(3, 3, 3, 3, BUBBLE_GUM_PINK_COLOR);
	protected static final Border NON_FOCUS_BORDER = BorderFactory.createEmptyBorder(3, 3, 3, 3);
	protected static final AddressSetView EMPTY_ADDRESS_SET = new AddressSet();

	protected String owner;
	protected PluginTool tool;
	protected JComponent topComp;
	protected JComponent bottomComp;
	protected TitledPanel[] titlePanels = new TitledPanel[2];
	protected String leftTitlePrefix = "";
	protected String rightTitlePrefix = "";
	protected int currProgramIndex = LEFT; // Side with current focus (LEFT or RIGHT)
	protected Program[] programs = new Program[2];
	protected Function[] functions = new Function[2];
	protected Data[] data = new Data[2];

	/** If true, the title of each comparison panel will be shown */
	private boolean showTitles = true;

	private boolean syncScrolling = false;

	private T fieldPanelCoordinator;

	/**
	 * Constructor
	 * 
	 * @param owner the name of the owner of this component 
	 * @param tool the tool that contains the component
	 */
	protected CodeComparisonPanel(String owner, PluginTool tool) {
		this.owner = owner;
		this.tool = tool;
	}

	/**
	 * The GUI component for this CodeComparisonPanel
	 * 
	 * @return the component
	 */
	public abstract JComponent getComponent();

	/**
	 * The title for this code comparison panel
	 * 
	 * @return the title
	 */
	public abstract String getTitle();

	/**
	 * Specifies the two programs to be compared by this panel
	 * 
	 * @param leftProgram the program for the left side
	 * @param rightProgram the program for the right side
	 */
	protected abstract void setPrograms(Program leftProgram, Program rightProgram);

	/**
	 * Displays a comparison of two program's functions
	 * 
	 * @param leftFunction the function to show in the left side of the code comparison view
	 * @param rightFunction the function to show in the right side of the code comparison view
	 */
	public abstract void loadFunctions(Function leftFunction, Function rightFunction);

	/**
	 * Displays a comparison of two program's data items
	 * 
	 * @param leftData the data item to show in the left side of the code comparison view
	 * @param rightData the data item to show in the right side of the code comparison view
	 */
	public abstract void loadData(Data leftData, Data rightData);

	/**
	 * Displays program information for a particular set of addresses in the two programs 
	 * being compared
	 * 
	 * @param leftProgram the program in the left side of the code comparison view
	 * @param rightProgram the program in the right side of the code comparison view
	 * @param leftAddresses the addresses of the program info to show in the left side
	 * @param rightAddresses the addresses of the program info to show in the right side
	 */
	public abstract void loadAddresses(Program leftProgram, Program rightProgram,
			AddressSetView leftAddresses, AddressSetView rightAddresses);

	/**
	 * Cleans up resources when this panel is no longer needed
	 */
	public abstract void dispose();

	/**
	 * Enable/disable navigation in this panel using the mouse
	 * 
	 * @param enabled false disables mouse navigation
	 */
	public abstract void setMouseNavigationEnabled(boolean enabled);

	/**
	 * Returns the actions for this panel
	 * 
	 * @return an array of docking actions
	 */
	public DockingAction[] getActions() {
		// No actions currently that appear for each CodeComparisonPanel.
		// Classes that extend this class will override this method to get all actions 
		// specific to that CodeComparisonPanel.
		DockingAction[] actions = new DockingAction[] {};
		return actions;
	}

	public boolean getShowTitles() {
		return showTitles;
	}

	public void setShowTitles(boolean showTitles) {
		this.showTitles = showTitles;
	}

	/**
	 * Determines if this panel is intended to take the place of another and if so it returns 
	 * the class of the panel to be superseded.
	 * @return the class for the CodeComparisonPanel that this one supersedes 
	 * or null if it doesn't supersede another panel.
	 */
	public abstract Class<? extends CodeComparisonPanel<T>> getPanelThisSupersedes();

	/**
	 * Returns the context object which corresponds to the area of focus within this provider's 
	 * component. Null is returned when there is no context.
	 * @param componentProvider the provider that includes this code comparison component.
	 * @param event mouse event which corresponds to this request.
	 * May be null for key-stroke or other non-mouse event.
	 * @return the action context for the area of focus in this component.
	 */
	public abstract ActionContext getActionContext(ComponentProvider componentProvider,
			MouseEvent event);

	/**
	 * Called when the indicated program has been restored because of an Undo/Redo.
	 * This method allows this CodeComparisonPanel to take an appropriate action (such as
	 * refreshing itself) to respond to the program changing.
	 * @param program the program that was restored.
	 */
	public abstract void programRestored(Program program);

	/**
	 * Determines if the left code panel currently has focus.
	 * @return true if the left side of the code comparison has focus.
	 */
	public abstract boolean leftPanelHasFocus();

	/**
	 * A CodeComparisonPanel should provide a title based on what the code comparison panel
	 * is displaying. This method sets a prefix string that should be prepended to each
	 * of the code comparison panel's titles.
	 * @param leftTitlePrefix the prefix string to prepend to the left panel's title.
	 * @param rightTitlePrefix the prefix string to prepend to the right panel's title.
	 */
	public abstract void setTitlePrefixes(String leftTitlePrefix, String rightTitlePrefix);

	/**
	 * Gets the program being viewed in the left side of this panel.
	 * @return the program or null
	 */
	public Program getLeftProgram() {
		return programs[LEFT];
	}

	/**
	 * Gets the program being viewed in the right side of this panel.
	 * @return the program or null
	 */
	public Program getRightProgram() {
		return programs[RIGHT];
	}

	/**
	 * Gets the function loaded in the left side of this panel.
	 * @return the function or null
	 */
	public Function getLeftFunction() {
		return functions[LEFT];
	}

	/**
	 * Gets the function loaded in the right side of this panel.
	 * @return the function or null
	 */
	public Function getRightFunction() {
		return functions[RIGHT];
	}

	/**
	 * Gets the data loaded in the left side of this panel.
	 * @return the data or null
	 */
	public Data getLeftData() {
		return data[LEFT];
	}

	/**
	 * Gets the data loaded in the right side of this panel.
	 * @return the data or null
	 */
	public Data getRightData() {
		return data[RIGHT];
	}

	/**
	 * Gets the addresses loaded in the left side of this panel.
	 * @return the addresses or an empty set
	 */
	public abstract AddressSetView getLeftAddresses();

	/**
	 * Gets the addresses loaded in the right side of this panel.
	 * @return the addresses or an empty set
	 */
	public abstract AddressSetView getRightAddresses();

	/**
	 * Refreshes the left side of this panel.
	 */
	public abstract void refreshLeftPanel();

	/**
	 * Refreshes the right side of this panel.
	 */
	public abstract void refreshRightPanel();

	@Override
	public void focusLost(FocusEvent e) {
		// Do nothing.
	}

	/**
	 * Updates the enablement for any actions created by this code comparison panel.
	 */
	public abstract void updateActionEnablement();

	/**
	 * Sets the coordinator for the two views within this code comparison panel. It coordinates
	 * their scrolling and location synchronization.
	 * @param fieldPanelCoordinator the coordinator for the two views
	 */
	public void setFieldPanelCoordinator(T fieldPanelCoordinator) {
		if (this.fieldPanelCoordinator != null) {
			this.fieldPanelCoordinator.dispose();
		}
		this.fieldPanelCoordinator = fieldPanelCoordinator;
	}

	/**
	 * Gets the current field panel coordinator used to synchronize scrolling between the 
	 * left and right view for this CodeComparisonPanel.
	 * @return the current FieldPanelCoordinator. Otherwise, null if scrolling is not 
	 * currently synchronized.
	 */
	protected T getFieldPanelCoordinator() {
		return fieldPanelCoordinator;
	}

	/**
	 * Creates a new FieldPanelCoordinator used to synchronize scrolling between the 
	 * left and right view for this CodeComparisonPanel.
	 * @return a new FieldPanelCoordinator
	 */
	protected abstract T createFieldPanelCoordinator();

	/**
	 * Gets the left field panel for this CodeComparisonPanel.
	 * @return the left FieldPanel.
	 */
	public abstract FieldPanel getLeftFieldPanel();

	/**
	 * Gets the right field panel for this CodeComparisonPanel.
	 * @return the right FieldPanel.
	 */
	public abstract FieldPanel getRightFieldPanel();

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
		this.syncScrolling = syncScrolling;

		// Refresh the left panel.
		FieldPanel leftPanel = getLeftFieldPanel();
		leftPanel.validate();
		leftPanel.invalidate();
		// Refresh the right panel.
		FieldPanel rightPanel = getRightFieldPanel();
		rightPanel.validate();
		rightPanel.invalidate();

		setFieldPanelCoordinator(syncScrolling ? createFieldPanelCoordinator() : null);
	}
}
