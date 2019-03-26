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

import java.awt.event.MouseEvent;
import java.util.*;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.DockingActionIf;
import docking.widgets.fieldpanel.internal.FieldPanelCoordinator;
import ghidra.app.util.viewer.listingpanel.ListingCodeComparisonPanel;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.app.util.viewer.util.CodeComparisonPanel;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

/**
 * This is the dockable provider that displays a FunctionComparisonPanel.
 */
public class FunctionComparisonProvider extends ComponentProviderAdapter implements PopupListener {

	private static final String HELP_TOPIC = "FunctionComparison";
	private static final Icon ICON = ResourceManager.loadImage("images/page_white_c.png");
	private FunctionComparisonPanel functionComparisonPanel;
	private FunctionComparisonProviderListener listener;

	/**
	 * Creates a provider for displaying a FunctionComparisonPanel that allows two or more
	 * functions to be compared. This constructor will load the functions so they are available
	 * for display in both the left side and right side of the panel. By default the first function 
	 * will be loaded into the left side and the second function will be loaded in the right side.
	 * @param plugin the plugin that owns this provider.
	 * @param functions the functions that are used to populate both the left and right side
	 * of the function comparison panel.
	 * @param listener the listener to notify when the provider is closing.
	 */
	public FunctionComparisonProvider(Plugin plugin, Function[] functions,
			FunctionComparisonProviderListener listener) {
		super(plugin.getTool(), "Function Comparison", plugin.getName());
		this.listener = listener;
		if (ICON != null) {
			setIcon(ICON);
		}
		functionComparisonPanel = new MultiFunctionComparisonPanel(this, tool, functions);
		initFunctionComparisonPanel();
	}

	/**
	 * Creates a provider for displaying two or more functions to be compared. This will load the 
	 * functions so the leftFunctions are available for display in the left side and the 
	 * rightFunctions are available for display in the right side of the function comparison panel. 
	 * By default the first function from each array will be the one initially displayed in its
	 * associated side.
	 * @param plugin the plugin that owns this provider.
	 * @param leftFunctions the functions that are used to populate the left side
	 * @param rightFunctions the functions that are used to populate the right side
	 * @param listener the listener to notify when the provider is closing.
	 */
	public FunctionComparisonProvider(Plugin plugin, Function[] leftFunctions,
			Function[] rightFunctions, FunctionComparisonProviderListener listener) {
		super(plugin.getTool(), "FunctionComparison", plugin.getName());
		this.listener = listener;
		if (ICON != null) {
			setIcon(ICON);
		}
		functionComparisonPanel =
			new MultiFunctionComparisonPanel(this, tool, leftFunctions, rightFunctions);
		initFunctionComparisonPanel();
	}

	/**
	 * Creates a provider for displaying two or more functions to be compared. This will load 
	 * the functions so the leftFunctions are available for display in the left side. For 
	 * each left side function there is a list of right side functions for comparison. 
	 * rightFunctions are available for display in the right side of the function comparison panel. 
	 * By default the first function from each array will be the one initially displayed in its
	 * associated side.
	 * @param plugin the plugin that owns this provider.
	 * @param functionMap maps each left function to its own set of right functions for comparison.
	 * @param listener the listener to notify when the provider is closing.
	 */
	public FunctionComparisonProvider(Plugin plugin,
			HashMap<Function, HashSet<Function>> functionMap,
			FunctionComparisonProviderListener listener) {

		super(plugin.getTool(), "FunctionComparison", plugin.getName());
		this.listener = listener;
		if (ICON != null) {
			setIcon(ICON);
		}
		functionComparisonPanel = new MappedFunctionComparisonPanel(this, tool, functionMap);
		initFunctionComparisonPanel();
	}

	/**
	 * Perform initialization for this provider and its panel. This includes setting the
	 * tab text, getting actions, establishing the popup listener, and specifying help.
	 */
	private void initFunctionComparisonPanel() {
		setTransient();
		setTabText(functionComparisonPanel);
		addSpecificCodeComparisonActions();
		tool.addPopupListener(this);
		setHelpLocation(new HelpLocation(HELP_TOPIC, "Function Comparison"));
	}

	/**
	 * Creates the text that is displayed on the tab for this provider.
	 * @param functionCompPanel the function comparison panel for this provider.
	 */
	private void setTabText(FunctionComparisonPanel functionCompPanel) {
		Function leftFunction = functionCompPanel.getLeftFunction();
		Function rightFunction = functionCompPanel.getRightFunction();
		String tabText = (leftFunction == null && rightFunction == null) ? "No Functions Yet"
				: getTabText(leftFunction, rightFunction);
		setTabText(tabText);
	}

	private String getTabText(Function function1, Function function2) {
		return ((function1 != null) ? function1.getName() : "none") + " & " +
			((function2 != null) ? function2.getName() : "none");
	}

	private void addSpecificCodeComparisonActions() {
		DockingAction[] actions = functionComparisonPanel.getCodeComparisonActions();
		for (DockingAction dockingAction : actions) {
			addLocalAction(dockingAction);
		}
	}

	@Override
	public FunctionComparisonPanel getComponent() {
		return functionComparisonPanel;
	}

	@Override
	public String toString() {
		StringBuffer buff = new StringBuffer();
		buff.append("FunctionComparisonProvider\n");
		buff.append("Name: ");
		buff.append(getName() + "\n");
		Function leftFunction = functionComparisonPanel.getLeftFunction();
		String leftName = (leftFunction != null) ? leftFunction.getName() : "No Function";
		buff.append("Function 1: " + leftName + "\n");
		Function rightFunction = functionComparisonPanel.getRightFunction();
		String rightName = (rightFunction != null) ? rightFunction.getName() : "No Function";
		buff.append("Function 2: " + rightName + "\n");
		buff.append("tool = " + tool + "\n");
		return buff.toString();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		CodeComparisonPanel<? extends FieldPanelCoordinator> currentComponent =
			functionComparisonPanel.getCurrentComponent();
		return currentComponent.getActionContext(this, event);
	}

	@Override
	public void removeFromTool() {
		tool.removePopupListener(this);

		super.removeFromTool();
	}

	@Override
	public void closeComponent() {
		super.closeComponent();

		if (listener != null) {
			listener.providerClosed(this);
		}
	}

	/**
	 * Indicates that the specified program has been closed, so this provider can close its 
	 * component, if any of its functions were from that program.
	 * @param program the program that was closed.
	 */
	public void programClosed(Program program) {
		// For now close the panel if it has any functions with this program.
		Function[] functions = functionComparisonPanel.getFunctions();
		for (Function function : functions) {
			if ((function != null) && function.getProgram() == program) {
				closeComponent();
				return;
			}
		}
	}

	/**
	 * Indicates that the specified program has been restored, so this can refresh the code 
	 * comparison panel.
	 * @param program the program that was restored (undo/redo).
	 */
	public void programRestored(Program program) {
		CodeComparisonPanel<? extends FieldPanelCoordinator> comparePanel =
			functionComparisonPanel.getCurrentComponent();
		comparePanel.programRestored(program);
	}

	@Override
	public List<DockingActionIf> getPopupActions(ActionContext context) {
		if (context.getComponentProvider() == this) {
			ListingCodeComparisonPanel dualListingPanel =
				functionComparisonPanel.getDualListingPanel();
			if (dualListingPanel != null) {
				ListingPanel leftPanel = dualListingPanel.getLeftPanel();
				return leftPanel.getHeaderActions(getName());
			}
		}
		return new ArrayList<>();
	}

	/**
	 * Restores the function comparison provider's components to the indicated saved configuration state.
	 * @param saveState the configuration state to restore
	 */
	public void readConfigState(SaveState saveState) {
		functionComparisonPanel.readConfigState(getName(), saveState);
	}

	/**
	 * Saves the current configuration state of the components that compose the function comparison provider.
	 * @param saveState the new configuration state
	 */
	public void writeConfigState(SaveState saveState) {
		functionComparisonPanel.writeConfigState(getName(), saveState);
	}
}
