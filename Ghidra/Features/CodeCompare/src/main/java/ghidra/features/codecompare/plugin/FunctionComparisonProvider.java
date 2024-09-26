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
package ghidra.features.codecompare.plugin;

import static ghidra.util.datastruct.Duo.Side.*;

import java.awt.event.MouseEvent;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.Icon;

import docking.ActionContext;
import docking.Tool;
import docking.action.*;
import docking.action.builder.ActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import docking.actions.PopupActionProvider;
import docking.widgets.dialogs.TableSelectionDialog;
import generic.theme.GIcon;
import ghidra.app.plugin.core.functionwindow.FunctionRowObject;
import ghidra.app.plugin.core.functionwindow.FunctionTableModel;
import ghidra.app.services.*;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.features.base.codecompare.listing.ListingCodeComparisonPanel;
import ghidra.features.base.codecompare.model.*;
import ghidra.features.base.codecompare.panel.CodeComparisonPanel;
import ghidra.features.base.codecompare.panel.FunctionComparisonPanel;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.datastruct.Duo.Side;
import resources.Icons;
import util.CollectionUtils;
import utility.function.Callback;

/**
 * Dockable provider that displays function comparisons  Clients create/modify
 * these comparisons using the {@link FunctionComparisonService}, which in turn 
 * creates instances of this provider as-needed. 
 */
public class FunctionComparisonProvider extends ComponentProviderAdapter
		implements PopupActionProvider, FunctionComparisonModelListener {
	private static final String ADD_COMPARISON_GROUP = "A9_AddToComparison";
	private static final String NAV_GROUP = "A9 FunctionNavigate";
	private static final String REMOVE_FUNCTIONS_GROUP = "A9_RemoveFunctions";

	private static final Icon ADD_TO_COMPARISON_ICON =
		new GIcon("icon.plugin.functioncompare.open.function.table");
	private static final Icon NAV_FUNCTION_ICON = Icons.NAVIGATE_ON_INCOMING_EVENT_ICON;
	private static final Icon NEXT_FUNCTION_ICON =
		new GIcon("icon.plugin.functioncompare.function.next");
	private static final Icon PREVIOUS_FUNCTION_ICON =
		new GIcon("icon.plugin.functioncompare.function.previous");
	private static final Icon REMOVE_FUNCTION_ICON =
		new GIcon("icon.plugin.functioncompare.function.remove");

	private static final String HELP_TOPIC = "FunctionComparison";

	private FunctionComparisonPlugin plugin;
	private FunctionComparisonModel model;
	private MultiFunctionComparisonPanel functionComparisonPanel;

	private Callback closeListener = Callback.dummy();
	private ToggleDockingAction navigateToAction;

	public FunctionComparisonProvider(FunctionComparisonPlugin plugin,
			FunctionComparisonModel model, Callback closeListener) {
		super(plugin.getTool(), "Function Comparison Provider", plugin.getName());
		this.plugin = plugin;
		this.model = model;
		this.closeListener = Callback.dummyIfNull(closeListener);

		functionComparisonPanel = new MultiFunctionComparisonPanel(this, tool, model);
		model.addFunctionComparisonModelListener(this);

		setTabText(functionComparisonPanel.getDescription());
		tool.addPopupActionProvider(this);
		setHelpLocation(new HelpLocation(HELP_TOPIC, "Function Comparison"));

		createActions();
		addSpecificCodeComparisonActions();
		setTransient();
		addToTool();
		setVisible(true);
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
		buff.append("Tab Text: ");
		buff.append(getTabText() + "\n");
		buff.append(functionComparisonPanel.getDescription());
		buff.append("tool = " + tool + "\n");
		return buff.toString();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		CodeComparisonPanel currentComponent =
			functionComparisonPanel.getCurrentComponent();
		return currentComponent.getActionContext(this, event);
	}

	@Override
	public void modelDataChanged() {
		updateTabAndTitle();
		tool.contextChanged(this);

		// The component will be disposed if all functions are gone. Do this later to prevent
		// concurrent modification exception since we are in a listener callback.
		Swing.runLater(this::closeIfEmpty);
	}

	@Override
	public void activeFunctionChanged(Side side, Function function) {
		updateTabAndTitle();
		tool.contextChanged(this);
		if (navigateToAction.isSelected()) {
			goToFunction(function);
		}
	}

	@Override
	public void contextChanged() {
		super.contextChanged();
		maybeGoToActiveFunction();
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool t, ActionContext context) {
		if (context.getComponentProvider() == this) {
			ListingCodeComparisonPanel dualListingPanel =
				functionComparisonPanel.getDualListingPanel();
			if (dualListingPanel != null) {
				ListingPanel leftPanel = dualListingPanel.getListingPanel(LEFT);
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
	 * Removes any functions being displayed by this provider that are from
	 * the given program. If there are no functions left to display, the
	 * provider is closed.
	 * 
	 * @param program the program being closed
	 */
	public void programClosed(Program program) {
		functionComparisonPanel.programClosed(program);
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
		model.removeFunctions(functions);
		closeIfEmpty();
	}

	/**
	 * Indicates that the specified program has been restored, so the 
	 * comparison panel should be refreshed
	 * 
	 * @param program the program that was restored (undo/redo)
	 */
	public void programRestored(Program program) {
		CodeComparisonPanel comparePanel =
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

	@Override
	public void removeFromTool() {
		tool.removePopupActionProvider(this);
		super.removeFromTool();
		dispose();
	}

	private void updateTabAndTitle() {
		String description = functionComparisonPanel.getDescription();
		setTabText(description);
		setTitle(description);

	}

	private void createActions() {
		new ActionBuilder("Compare Next Function", plugin.getName())
				.description("Compare the next function for the side with focus.")
				.helpLocation(new HelpLocation(HELP_TOPIC, "Navigate Next"))
				.keyBinding("control shift N")
				.popupMenuPath("Compare Next Function")
				.popupMenuGroup(NAV_GROUP)
				.toolBarIcon(NEXT_FUNCTION_ICON)
				.toolBarGroup(NAV_GROUP)
				.enabledWhen(c -> functionComparisonPanel.canCompareNextFunction())
				.onAction(c -> functionComparisonPanel.compareNextFunction())
				.buildAndInstallLocal(this);

		new ActionBuilder("Compare Previous Function", plugin.getName())
				.description("Compare the previous function for the side with focus.")
				.helpLocation(new HelpLocation(HELP_TOPIC, "Navigate Previous"))
				.keyBinding("control shift P")
				.popupMenuPath("Compare Previous Function")
				.popupMenuGroup(NAV_GROUP)
				.toolBarIcon(PREVIOUS_FUNCTION_ICON)
				.toolBarGroup(NAV_GROUP)
				.enabledWhen(c -> functionComparisonPanel.canComparePreviousFunction())
				.onAction(c -> functionComparisonPanel.comparePreviousFunction())
				.buildAndInstallLocal(this);

		new ActionBuilder("Remove Function", plugin.getName())
				.description("Removes the active function from the comparison")
				.helpLocation(new HelpLocation(HELP_TOPIC, "Remove_From_Comparison"))
				.keyBinding("control shift R")
				.popupMenuPath("Remove Function")
				.popupMenuGroup(REMOVE_FUNCTIONS_GROUP)
				.toolBarIcon(REMOVE_FUNCTION_ICON)
				.toolBarGroup(REMOVE_FUNCTIONS_GROUP)
				.enabledWhen(c -> functionComparisonPanel.canRemoveActiveFunction())
				.onAction(c -> functionComparisonPanel.removeActiveFunction())
				.buildAndInstallLocal(this);

		navigateToAction = new ToggleActionBuilder("Navigate to Selected Function",
			plugin.getName())
					.description(HTMLUtilities.toHTML("Toggle <b>On</b> means to navigate to " +
						"whatever function is selected in the comparison panel, when focus changes" +
						" or a new function is selected."))
					.helpLocation(new HelpLocation(HELP_TOPIC, "Navigate_To_Function"))
					.toolBarIcon(NAV_FUNCTION_ICON)
					.onAction(c -> maybeGoToActiveFunction())
					.buildAndInstallLocal(this);

		if (model instanceof AnyToAnyFunctionComparisonModel) {
			createDefaultModelActions();
		}
	}

	// Only the default model supports adding to the current comparison
	private void createDefaultModelActions() {
		new ActionBuilder("Add Functions To Comparison", plugin.getName())
				.description("Add functions to this comparison")
				.helpLocation(new HelpLocation(HELP_TOPIC, "Add_To_Comparison"))
				.popupMenuPath("Add Functions")
				.popupMenuGroup(ADD_COMPARISON_GROUP)
				.toolBarIcon(ADD_TO_COMPARISON_ICON)
				.toolBarGroup(ADD_COMPARISON_GROUP)
				.enabledWhen(c -> model instanceof AnyToAnyFunctionComparisonModel)
				.onAction(c -> addFunctions())
				.buildAndInstallLocal(this);

	}

	private void addFunctions() {
		ProgramManager service = tool.getService(ProgramManager.class);
		Program currentProgram = service.getCurrentProgram();
		FunctionTableModel functionTableModel = new FunctionTableModel(tool, currentProgram);

		TableSelectionDialog<FunctionRowObject> diag = new TableSelectionDialog<>(
			"Select Functions: " + currentProgram.getName(), functionTableModel, true);
		tool.showDialog(diag);
		List<FunctionRowObject> rows = diag.getSelectionItems();
		if (CollectionUtils.isBlank(rows)) {
			return; // the table chooser can return null if the operation was cancelled
		}

		List<Function> functions =
			rows.stream().map(row -> row.getFunction()).collect(Collectors.toList());

		if (model instanceof AnyToAnyFunctionComparisonModel defaultModel) {
			defaultModel.addFunctions(functions);
		}

	}

	private void maybeGoToActiveFunction() {
		if (navigateToAction.isSelected()) {
			Side activeSide = functionComparisonPanel.getActiveSide();
			Function function = model.getActiveFunction(activeSide);
			goToFunction(function);
		}
	}

	private void goToFunction(Function function) {
		GoToService goToService = tool.getService(GoToService.class);
		if (goToService == null) {
			Msg.warn(this, "Can't navigate to selected function because GoToService is missing!");
			return;
		}
		goToService.goTo(function.getEntryPoint(), function.getProgram());
	}

	/**
	 * Closes this provider if there are no comparisons to view
	 */
	private void closeIfEmpty() {
		if (model.isEmpty()) {
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

	public CodeComparisonPanel getCodeComparisonPanelByName(String name) {
		return functionComparisonPanel.getCodeComparisonPanelByName(name);
	}

	private void dispose() {
		plugin.providerClosed(this);
		closeListener.call();
		closeListener = Callback.dummy();
		functionComparisonPanel.dispose();
	}

	@Override
	public void componentActivated() {
		plugin.providerActivated(this);
	}

	/**
	 * Returns true if this provider is using the {@link AnyToAnyFunctionComparisonModel} which
	 * allows adding functions. The other model ({@link MatchedFunctionComparisonModel} ) only 
	 * allows functions to be added in matched pairs.
	 * @return true if this provider supports adding functions to the comparison
	 */
	public boolean supportsAddingFunctions() {
		return model instanceof AnyToAnyFunctionComparisonModel;
	}

	/**
	 * Adds functions to the comparison model if the model supports it.
	 * @param functions the functions to add to the comparison
	 */
	public void addFunctions(Collection<Function> functions) {
		if (model instanceof AnyToAnyFunctionComparisonModel anyToAnyModel) {
			anyToAnyModel.addFunctions(functions);
		}
	}
}
