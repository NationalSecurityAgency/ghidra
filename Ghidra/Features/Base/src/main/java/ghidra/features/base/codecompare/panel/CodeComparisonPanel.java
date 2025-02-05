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
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.border.Border;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.*;
import docking.widgets.TitledPanel;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.datastruct.Duo;
import ghidra.util.datastruct.Duo.Side;

/**
 * The CodeComparisonPanel class should be extended by any class that is to be 
 * discovered by the {@link FunctionComparisonPanel} class and included as a 
 * form of comparing two sections of code within the same or different programs
 * <p>
 * NOTE: ALL CodeComparisonPanel CLASSES MUST END IN
 * <code>CodeComparisonPanel</code> so they are discoverable by the {@link ClassSearcher} 
 */
public abstract class CodeComparisonPanel extends JPanel
		implements ExtensionPoint {
	public static final String HELP_TOPIC = "FunctionComparison";
	private static final Color ACTIVE_BORDER_COLOR = Palette.getColor("lightpink");
	private static final int MINIMUM_PANEL_WIDTH = 50;
	private static final Border NON_ACTIVE_BORDER = BorderFactory.createEmptyBorder(3, 3, 3, 3);
	private static final Border ACTIVE_BORDER =
		BorderFactory.createMatteBorder(3, 3, 3, 3, ACTIVE_BORDER_COLOR);

	protected String owner;
	protected PluginTool tool;

	protected Duo<ComparisonData> comparisonData = new Duo<>(EMPTY, EMPTY);
	private Duo<String> titlePrefixes = new Duo<>("", "");
	private Duo<TitledPanel> titlePanels = new Duo<>();

	protected Side activeSide = LEFT;
	private JSplitPane splitPane;
	private ToggleOrientationAction toggleOrientationAction;
	private JComponent northComponent;
	private boolean showTitles = true;

	/**
	 * Constructor
	 * 
	 * @param owner the name of the owner of this component 
	 * @param tool the tool that contains the component
	 */
	protected CodeComparisonPanel(String owner, PluginTool tool) {
		this.owner = owner;
		this.tool = tool;
		toggleOrientationAction = new ToggleOrientationAction(getName());

		// Important! Subclasses must call the build() method instead of calling it here. This is 
		// to avoid java's constructor ordering problem
	}

	public PluginTool getTool() {
		return tool;
	}

	/**
	 * Displays a comparison of two ComparisonData objects
	 * 
	 * @param left the comparisonData for the left side
	 * @param right the comparisonData for the right side
	 */
	public void loadComparisons(ComparisonData left, ComparisonData right) {
		if (comparisonData.equals(left, right)) {
			return;
		}
		comparisonData = new Duo<>(left, right);
		comparisonDataChanged();
		updateTitles();
	}

	/**
	 * Clears out the current comparisonDatas
	 */
	public void clearComparisons() {
		loadComparisons(ComparisonData.EMPTY, ComparisonData.EMPTY);
	}

	/**
	 * Returns the actions for this panel
	 * 
	 * @return an array of docking actions
	 */
	public List<DockingAction> getActions() {
		List<DockingAction> actionList = new ArrayList<>();
		actionList.add(toggleOrientationAction);
		return actionList;
	}

	/**
	 * Toggles whether or not to display data titles for each side.
	 * @param showTitles true to show data titles
	 */
	public void setShowDataTitles(boolean showTitles) {
		this.showTitles = showTitles;
	}

	/**
	 * Returns true if dual panels are displayed horizontally, false if displayed vertically.
	 * @return true if dual panels are displayed horizontally, false if displayed vertically
	 */
	public boolean isSideBySide() {
		return toggleOrientationAction.isSelected();
	}

	/**
	 * Sets the orientation for the dual panels.
	 * @param b if true, panels will be display horizontally, otherwise vertically
	 */
	public void setSideBySide(boolean b) {
		toggleOrientationAction.setSelected(b);
		updateOrientation();
	}

	/**
	 * Force subclasses to supply a descriptive name.
	 * 
	 * @return a descriptive name for this panel type
	 */
	@Override
	public abstract String getName();

	/**
	 * Cleans up resources when this panel is no longer needed
	 */
	public abstract void dispose();

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
	public void programRestored(Program program) {
		updateTitles();
	}

	/**
	 * Called when a program is closed.
	 * @param program the closed program
	 */
	public void programClosed(Program program) {
		// do nothing by default
	}

	/**
	 * Returns the {@link Side} that is currently active
	 * @return the {@link Side} that is currently active
	 */
	public Side getActiveSide() {
		return activeSide;
	}

	/**
	 * Sets the component displayed in the top of this panel.
	 * 
	 * @param component the component.
	 */
	public void setTopComponent(JComponent component) {
		if (northComponent != null) {
			remove(northComponent);
		}
		northComponent = component;
		if (northComponent != null) {
			add(northComponent, BorderLayout.NORTH);
		}
		validate();
	}

	/**
	 * A CodeComparisonPanel should provide a title based on what the code comparison panel
	 * is displaying. This method sets a prefix string that should be prepended to each
	 * of the code comparison panel's titles.
	 * @param leftTitlePrefix the prefix string to prepend to the left panel's title.
	 * @param rightTitlePrefix the prefix string to prepend to the right panel's title.
	 */
	public void setTitlePrefixes(String leftTitlePrefix, String rightTitlePrefix) {
		titlePrefixes = new Duo<>(leftTitlePrefix, rightTitlePrefix);
		updateTitles();
	}

	/**
	 * Returns the program being shown in the given side.
	 * @param side the {@link Side} to get the program for
	 * @return the program for the given side.
	 */
	public Program getProgram(Side side) {
		return comparisonData.get(side).getProgram();
	}

	/**
	 * Returns the function being shown in the given side.
	 * @param side the {@link Side} to get the function for
	 * @return the function for the given side.
	 */
	public Function getFunction(Side side) {
		return comparisonData.get(side).getFunction();
	}

	/**
	 * Returns the addresses being shown in the given side.
	 * @param side the {@link Side} to get the program for
	 * @return the address set for the given side
	 */
	public AddressSetView getAddresses(Side side) {
		return comparisonData.get(side).getAddressSet();
	}

	/**
	* Updates the enablement for any actions created by this code comparison panel.
	*/
	public abstract void updateActionEnablement();

	/**
	 * Sets whether or not scrolling is synchronized.
	 * @param b true means synchronize scrolling between the two views.
	 */
	public abstract void setSynchronizedScrolling(boolean b);

	/**
	 * Returns the Component for the given {@link Side}
	 * @param side the Side to its component
	 * @return the Component for the given {@link Side}
	 */
	public abstract JComponent getComparisonComponent(Side side);

	/**
	 * Notification to subclasses that the comparison data has changed
	 */
	protected abstract void comparisonDataChanged();

	private final String getTitle(Side side) {
		return comparisonData.get(side).getDescription();
	}

	private void updateTitles() {
		updateTitle(Side.LEFT);
		updateTitle(Side.RIGHT);
	}

	private void updateTitle(Side side) {
		String title = showTitles ? getTitle(side) : "";
		setTitle(titlePanels.get(side), titlePrefixes.get(side), title);
	}

	private void updateOrientation() {
		int orientation = toggleOrientationAction.isSelected() ? JSplitPane.HORIZONTAL_SPLIT
				: JSplitPane.VERTICAL_SPLIT;
		splitPane.setOrientation(orientation);
		splitPane.setDividerLocation(0.5);
	}

	private void setTitle(TitledPanel titlePanel, String titlePrefix, String title) {
		if (!titlePrefix.isEmpty()) {
			titlePrefix += " "; // Add a space between prefix and title.
		}
		String htmlPrefix = "<html>";
		if (title.startsWith(htmlPrefix)) {
			titlePanel.setTitleName(htmlPrefix + HTMLUtilities.friendlyEncodeHTML(titlePrefix) +
				title.substring(htmlPrefix.length()));
		}
		else {
			titlePanel.setTitleName(titlePrefix + title);
		}
	}

	protected final void buildPanel() {
		setLayout(new BorderLayout());

		TitledPanel leftPanel = new TitledPanel(getTitle(LEFT), getComparisonComponent(LEFT), 5);
		TitledPanel rightPanel = new TitledPanel(getTitle(RIGHT), getComparisonComponent(RIGHT), 5);
		titlePanels = new Duo<>(leftPanel, rightPanel);

		// Set the MINIMUM_PANEL_WIDTH for the left and right panel to prevent the split pane's
		// divider from becoming locked (can't be moved) due to extra long title names.
		titlePanels.get(LEFT)
				.setMinimumSize(
					new Dimension(MINIMUM_PANEL_WIDTH,
						titlePanels.get(LEFT).getMinimumSize().height));
		titlePanels.get(RIGHT)
				.setMinimumSize(
					new Dimension(MINIMUM_PANEL_WIDTH,
						titlePanels.get(RIGHT).getMinimumSize().height));

		splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, true, titlePanels.get(LEFT),
			titlePanels.get(RIGHT));
		splitPane.setResizeWeight(0.5);
		splitPane.setDividerSize(4);
		splitPane.setBorder(BorderFactory.createEmptyBorder());
		add(splitPane, BorderLayout.CENTER);
		updateOrientation();

		addMouseAndFocusListeners(LEFT);
		addMouseAndFocusListeners(RIGHT);
		setActiveSide(LEFT);
	}

	private void addMouseAndFocusListeners(Side side) {
		JComponent comp = getComparisonComponent(side);
		comp.addFocusListener(new FocusAdapter() {
			@Override
			public void focusGained(FocusEvent e) {
				setActiveSide(side);
				updateContextForFocusGained(e.getComponent());
			}
		});

		comp = getComparisonComponent(side);

		MouseAdapter mouseListener = new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				setActiveSide(side);
			}
		};

		addMouseListenerRecursively(comp, mouseListener);
	}

	private void updateContextForFocusGained(Component component) {
		ComponentProvider provider = tool.getWindowManager().getProvider(component);
		if (provider != null) {
			provider.contextChanged();
		}

	}

	private void addMouseListenerRecursively(Component component, MouseListener listener) {
		component.addMouseListener(listener);
		if (component instanceof Container container) {
			for (int i = 0; i < container.getComponentCount(); i++) {
				Component child = container.getComponent(i);
				addMouseListenerRecursively(child, listener);
			}
		}
	}

	protected void setActiveSide(Side side) {
		activeSide = side;
		getComparisonComponent(side).setBorder(ACTIVE_BORDER);
		getComparisonComponent(side.otherSide()).setBorder(NON_ACTIVE_BORDER);
	}

	private class ToggleOrientationAction extends ToggleDockingAction {
		ToggleOrientationAction(String name) {
			super(name + " Toggle Orientation", "FunctionComparison");
			setDescription(
				"<html>Toggle the layout to be either side by side or one above the other");
			setHelpLocation(
				new HelpLocation("FunctionComparison", "Dual_" + name + "_Toggle_Orientation"));
			setEnabled(true);
			MenuData menuData =
				new MenuData(new String[] { "Show " + name + " Side-by-Side" }, "Orientation");
			setMenuBarData(menuData);
			setSelected(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			updateOrientation();
		}
	}

}
