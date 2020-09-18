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

import docking.ActionContext;
import docking.Tool;
import docking.action.DockingAction;
import docking.action.DockingActionIf;
import docking.actions.PopupActionProvider;
import docking.widgets.fieldpanel.internal.FieldPanelCoordinator;
import ghidra.app.services.FunctionComparisonModel;
import ghidra.app.services.FunctionComparisonService;
import ghidra.app.util.viewer.listingpanel.ListingCodeComparisonPanel;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.app.util.viewer.util.CodeComparisonPanel;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

/**
 * Dockable provider that displays function comparisons  Clients create/modify
 * these comparisons using the {@link FunctionComparisonService}, which in turn 
 * creates instances of this provider as-needed. 
 */
public class FunctionComparisonProvider extends ComponentProviderAdapter
		implements PopupActionProvider, FunctionComparisonModelListener {

	protected static final String HELP_TOPIC = "FunctionComparison";
	protected FunctionComparisonPanel functionComparisonPanel;
	protected Plugin plugin;

	/** Contains all the comparison data to be displayed by this provider */
	protected FunctionComparisonModel model;

	/**
	 * Constructor
	 * 
	 * @param plugin the active plugin
	 * @param name the providers name; used to group similar providers into a tab within
	 *        the same window
	 * @param owner the provider owner, usually a plugin name
	 */
	public FunctionComparisonProvider(Plugin plugin, String name, String owner) {
		this(plugin, name, owner, null);
	}

	/**
	 * Constructor
	 * 
	 * @param plugin the active plugin
	 * @param name the providers name; used to group similar providers into a tab within
	 *        the same window
	 * @param owner the provider owner, usually a plugin name
	 * @param contextType the type of context supported by this provider; may be null
	 */
	public FunctionComparisonProvider(Plugin plugin, String name, String owner,
			Class<?> contextType) {
		super(plugin.getTool(), name, owner, contextType);
		this.plugin = plugin;
		model = new FunctionComparisonModel();
		model.addFunctionComparisonModelListener(this);
		functionComparisonPanel = getComponent();
		initFunctionComparisonPanel();
	}

	@Override
	public FunctionComparisonPanel getComponent() {
		if (functionComparisonPanel == null) {
			functionComparisonPanel = new FunctionComparisonPanel(this, tool, null, null);
		}
		return functionComparisonPanel;
	}

	@Override
	public String toString() {
		StringBuffer buff = new StringBuffer();
		buff.append("FunctionComparisonProvider\n");
		buff.append("Name: ");
		buff.append(getName() + "\n");
		buff.append("Tab Text: ");
		buff.append(getTabText() + "\n");
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
		tool.removePopupActionProvider(this);
		super.removeFromTool();
	}

	@Override
	public void modelChanged(List<FunctionComparison> data) {
		this.model.setComparisons(data);
		functionComparisonPanel.reload();
		setTabText(functionComparisonPanel.getDescription());
		closeIfEmpty();
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool t, ActionContext context) {
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
	 * Returns the comparison model
	 * 
	 * @return the comparison model
	 */
	public FunctionComparisonModel getModel() {
		return model;
	}

	/**
	 * Replaces the comparison model with the one provided
	 * 
	 * @param model the comparison model
	 */
	public void setModel(FunctionComparisonModel model) {
		this.model = model;
	}

	/**
	 * Removes any functions being displayed by this provider that are from
	 * the given program. If there are no functions left to display, the
	 * provider is closed.
	 * 
	 * @param program the program being closed
	 */
	public void programClosed(Program program) {
		model.removeFunctions(program);
		closeIfEmpty();
	}

	/**
	 * Removes all functions for the specified program from the comparison
	 * model
	 * 
	 * @param program the program whose functions require removal
	 */
	public void removeFunctions(Program program) {
		model.removeFunctions(program);
		closeIfEmpty();
	}

	/**
	 * Removes the set of functions from the comparison model
	 * 
	 * @param functions the functions to remove
	 */
	public void removeFunctions(Set<Function> functions) {
		functions.stream().forEach(f -> model.removeFunction(f));
		closeIfEmpty();
	}

	/**
	 * Indicates that the specified program has been restored, so the 
	 * comparison panel should be refreshed
	 * 
	 * @param program the program that was restored (undo/redo)
	 */
	public void programRestored(Program program) {
		CodeComparisonPanel<? extends FieldPanelCoordinator> comparePanel =
			functionComparisonPanel.getCurrentComponent();
		comparePanel.programRestored(program);
	}

	/**
	 * Restores the function comparison providers components to the indicated 
	 * saved configuration state
	 * 
	 * @param saveState the configuration state to restore
	 */
	public void readConfigState(SaveState saveState) {
		functionComparisonPanel.readConfigState(getName(), saveState);
	}

	/**
	 * Saves the current configuration state of the components that compose 
	 * the function comparison provider
	 * 
	 * @param saveState the new configuration state
	 */
	public void writeConfigState(SaveState saveState) {
		functionComparisonPanel.writeConfigState(getName(), saveState);
	}

	/**
	 * Perform initialization for this provider and its panel
	 */
	protected void initFunctionComparisonPanel() {
		setTransient();
		setTabText(functionComparisonPanel.getDescription());
		addSpecificCodeComparisonActions();
		tool.addPopupActionProvider(this);
		setHelpLocation(new HelpLocation(HELP_TOPIC, "Function Comparison"));
	}

	/**
	 * Returns true if the comparison panel is empty
	 * 
	 * @return true if the panel is empty
	 */
	boolean isEmpty() {
		return functionComparisonPanel.isEmpty();
	}

	/**
	 * Closes this provider if there are no comparisons to view
	 */
	void closeIfEmpty() {
		if (isEmpty()) {
			closeComponent();
		}
	}

	/**
	 * Gets actions specific to the code comparison panel and adds them to this
	 * provider
	 */
	private void addSpecificCodeComparisonActions() {
		DockingAction[] actions = functionComparisonPanel.getCodeComparisonActions();
		for (DockingAction dockingAction : actions) {
			addLocalAction(dockingAction);
		}
	}
}
