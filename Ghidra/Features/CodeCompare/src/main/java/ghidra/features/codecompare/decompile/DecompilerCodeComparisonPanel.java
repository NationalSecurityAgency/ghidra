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
package ghidra.features.codecompare.decompile;

import static ghidra.util.datastruct.Duo.Side.*;

import java.awt.Component;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;
import javax.swing.JComponent;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.*;
import docking.options.OptionsService;
import generic.theme.GIcon;
import ghidra.app.decompiler.component.DecompileData;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.features.base.codecompare.panel.CodeComparisonPanel;
import ghidra.features.codecompare.graphanalysis.TokenBin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import ghidra.util.datastruct.Duo;
import ghidra.util.datastruct.Duo.Side;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskBuilder;
import ghidra.util.task.TaskLauncher;
import resources.Icons;
import resources.MultiIcon;

/**
 * Panel that displays two decompilers for comparison
 */
public class DecompilerCodeComparisonPanel
		extends CodeComparisonPanel {

	public static final String NAME = "Decompiler View";

	private boolean isStale = true;

	private Duo<CDisplay> cDisplays = new Duo<>();

	private DecompilerCodeComparisonOptions comparisonOptions;
	private CodeDiffFieldPanelCoordinator coordinator;
	private DecompileDataDiff decompileDataDiff;

	private ToggleExactConstantMatching toggleExactConstantMatchingAction;
	private List<DockingAction> actions = new ArrayList<>();
	private Duo<Function> functions = new Duo<>();

	/**
	 * Creates a comparison panel with two decompilers
	 * 
	 * @param owner the owner of this panel
	 * @param tool the tool displaying this panel
	 */
	public DecompilerCodeComparisonPanel(String owner, PluginTool tool) {
		super(owner, tool);
		comparisonOptions = new DecompilerCodeComparisonOptions(tool, () -> repaint());

		cDisplays = new Duo<>(buildCDisplay(LEFT), buildCDisplay(RIGHT));
		cDisplays.get(LEFT).initializeOptions(tool, getFunction(LEFT));
		cDisplays.get(RIGHT).initializeOptions(tool, getFunction(RIGHT));

		buildPanel();
		setSynchronizedScrolling(true);
		linkHighlightControllers();
		createActions();
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	protected void comparisonDataChanged() {

		maybeLoadFunction(LEFT, comparisonData.get(LEFT).getFunction());
		maybeLoadFunction(RIGHT, comparisonData.get(RIGHT).getFunction());
		if (coordinator != null) {
			coordinator.leftLocationChanged((ProgramLocation) null);
		}
	}

	public void maybeLoadFunction(Side side, Function function) {
		// we keep a local copy of the function so we know if it is already decompiled
		if (functions.get(side) == function) {
			return;
		}

		// Clear the scroll info and highlight info to prevent unnecessary highlighting, etc.
		loadFunction(side, null);
		loadFunction(side, function);

	}

	@Override
	public void dispose() {
		setSynchronizedScrolling(false); // disposes any exiting coordinator
		cDisplays.each(CDisplay::dispose);
		comparisonOptions = null;
	}

	/**
	 * Gets the display from the active side.
	 * @return the active display
	 */
	public CDisplay getActiveDisplay() {
		return cDisplays.get(activeSide);
	}

	/**
	 * Gets the left side's C display panel.
	 * @return the left C display panel
	 */
	public CDisplay getLeftPanel() {
		return cDisplays.get(LEFT);
	}

	/**
	 * Gets the right side's C display panel.
	 * @return the right C display panel
	 */
	public CDisplay getRightPanel() {
		return cDisplays.get(RIGHT);
	}

	@Override
	public List<DockingAction> getActions() {
		List<DockingAction> allActions = super.getActions();
		allActions.addAll(actions);
		return allActions;
	}

	@Override
	public ActionContext getActionContext(ComponentProvider provider, MouseEvent event) {

		Component component = event != null ? event.getComponent()
				: getActiveDisplay().getDecompilerPanel().getFieldPanel();

		DualDecompilerActionContext dualDecompContext =
			new DualDecompilerActionContext(provider, this, component);

		return dualDecompContext;
	}

	@Override
	public void programClosed(Program program) {
		cDisplays.each(c -> c.programClosed(program));
	}

	@Override
	public JComponent getComparisonComponent(Side side) {
		return cDisplays.get(side).getDecompilerPanel();
	}

	private void createActions() {
		toggleExactConstantMatchingAction = new ToggleExactConstantMatching(getClass().getName());

		actions.add(new DecompilerDiffViewFindAction(owner, tool));
		actions.add(new DecompilerCodeComparisonOptionsAction());
		actions.add(toggleExactConstantMatchingAction);
		actions.add(new CompareFuncsFromMatchedTokensAction(this, tool));
		actions.add(new ApplyLocalNameFromMatchedTokensAction(this, tool));
		actions.add(new ApplyGlobalNameFromMatchedTokensAction(this, tool));
		actions.add(new ApplyVariableTypeFromMatchedTokensAction(this, tool));
		actions.add(new ApplyEmptyVariableTypeFromMatchedTokensAction(this, tool));
		actions.add(new ApplyCalleeFunctionNameFromMatchedTokensAction(this, tool));
		actions.add(new ApplyCalleeEmptySignatureFromMatchedTokensAction(this, tool));
		actions.add(new ApplyCalleeSignatureWithDatatypesFromMatchedTokensAction(this, tool));
	}

	private void decompileDataSet(Side side, DecompileData dcompileData) {
		cDisplays.get(side).restoreCursorPosition();
		updateDiffs();
	}

	private boolean isMatchingConstantsExactly() {
		return !toggleExactConstantMatchingAction.isSelected();
	}

	private void loadFunction(Side side, Function function) {
		if (functions.get(side) != function) {
			functions = functions.with(side, function);
			cDisplays.get(side).showFunction(tool, function);
		}
	}

	private void locationChanged(Side side, ProgramLocation location) {
		if (coordinator != null) {
			if (side == LEFT) {
				coordinator.leftLocationChanged(location);
			}
			else {
				coordinator.rightLocationChanged(location);
			}
		}
	}

	private void updateDiffs() {
		DecompileData leftDecompileData = cDisplays.get(LEFT).getDecompileData();
		DecompileData rightDecompileData = cDisplays.get(RIGHT).getDecompileData();

		if (isValid(leftDecompileData) && isValid(rightDecompileData)) {
			decompileDataDiff = new DecompileDataDiff(leftDecompileData, rightDecompileData);
			determineDecompilerDifferences();
		}
	}

	private boolean isValid(DecompileData decompileData) {
		return decompileData != null && decompileData.isValid();
	}

	private CDisplay buildCDisplay(Side side) {
		return new CDisplay(getTool(), comparisonOptions,
			decompileData -> decompileDataSet(side, decompileData),
			l -> locationChanged(side, l));
	}

	private void linkHighlightControllers() {
		DiffClangHighlightController left = cDisplays.get(LEFT).getHighlightController();
		DiffClangHighlightController right = cDisplays.get(RIGHT).getHighlightController();
		left.addListener(right);
		right.addListener(left);

	}

	@Override
	public void setSynchronizedScrolling(boolean synchronize) {

		if (coordinator != null) {
			coordinator.dispose();
			coordinator = null;
		}

		if (synchronize) {
			coordinator = createCoordinator();
			doSynchronize();
		}
	}

	private void doSynchronize() {
		CDisplay activeDisplay = getActiveDisplay();
		ProgramLocation programLocation =
			activeDisplay.getDecompilerPanel().getCurrentLocation();
		if (activeDisplay == cDisplays.get(LEFT)) {
			coordinator.leftLocationChanged(programLocation);
		}
		else {
			coordinator.rightLocationChanged(programLocation);
		}
	}

	private CodeDiffFieldPanelCoordinator createCoordinator() {
		CodeDiffFieldPanelCoordinator panelCoordinator = new CodeDiffFieldPanelCoordinator(this);
		if (decompileDataDiff != null) {
			TaskBuilder.withRunnable(monitor -> {
				try {
					panelCoordinator.replaceDecompileDataDiff(decompileDataDiff,
						isMatchingConstantsExactly(), monitor);
				}
				catch (CancelledException e) {
					panelCoordinator.clearLineNumberPairing();
				}
			}).setTitle("Initializing Code Compare").launchNonModal();
		}
		return panelCoordinator;

	}

	private class DecompilerCodeComparisonOptionsAction extends DockingAction {

		DecompilerCodeComparisonOptionsAction() {
			super("Decompiler Code Comparison Options", owner);
			setDescription("Show the tool options for the Decompiler Code Comparison.");
			setPopupMenuData(new MenuData(new String[] { "Properties" }, null, "Z_Properties"));
			setHelpLocation(
				new HelpLocation("FunctionComparison", "Decompiler_Code_Comparison_Options"));
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return (context instanceof DualDecompilerActionContext);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			OptionsService service = tool.getService(OptionsService.class);
			service.showOptionsDialog("FunctionComparison", "Decompiler Code Comparison");
		}
	}

	@Override
	public void setVisible(boolean b) {
		super.setVisible(b);
		if (b && isStale) {
			determineDecompilerDifferences();
			isStale = false;
		}
		updateActionEnablement();
	}

	List<TokenBin> getHighBins() {
		return coordinator == null ? null : coordinator.getHighBins();
	}

	private void determineDecompilerDifferences() {
		if (decompileDataDiff == null) {
			return;
		}
		DiffClangHighlightController leftHighlights = cDisplays.get(LEFT).getHighlightController();
		DiffClangHighlightController rightHighlights =
			cDisplays.get(RIGHT).getHighlightController();
		DetermineDecompilerDifferencesTask task =
			new DetermineDecompilerDifferencesTask(decompileDataDiff, isMatchingConstantsExactly(),
				leftHighlights, rightHighlights, coordinator);

		new TaskLauncher(task, this);
	}

	@Override
	public void updateActionEnablement() {
		// Need to enable/disable toolbar button.
		toggleExactConstantMatchingAction.setEnabled(isVisible());
	}

	public boolean isBusy() {
		return cDisplays.get(LEFT).isBusy() || cDisplays.get(RIGHT).isBusy();
	}

	public DecompilerPanel getDecompilerPanel(Side side) {
		return cDisplays.get(side).getDecompilerPanel();
	}

	public class ToggleExactConstantMatching extends ToggleDockingAction {

		private final Icon EXACT_CONSTANT_MATCHING_ICON = new GIcon("icon.base.source.c");
		private final Icon NO_EXACT_CONSTANT_MATCHING_ICON =
			new MultiIcon(EXACT_CONSTANT_MATCHING_ICON, Icons.NOT_ALLOWED_ICON);

		/**
		 * Creates an action for toggling exact constant matching in the code diff's 
		 * dual decompiler.
		 * @param owner the owner of this action (typically the provider).
		 */
		public ToggleExactConstantMatching(String owner) {
			super("Toggle Exact Constant Matching", owner);
			setHelpLocation(new HelpLocation(HELP_TOPIC, "Toggle Exact Constant Matching"));

			this.setToolBarData(new ToolBarData(NO_EXACT_CONSTANT_MATCHING_ICON, "toggles"));

			setDescription(HTMLUtilities.toHTML("Toggle whether or not constants must\n" +
				"be exactly the same value to be a match\n" + "in the Decomiler Diff View."));
			setSelected(false);
			setEnabled(true);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (context instanceof DualDecompilerActionContext) {
				return true;
			}
			return false;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (isVisible()) {
				determineDecompilerDifferences();
			}
		}

		@Override
		public void setSelected(boolean selected) {
			getToolBarData().setIcon(
				selected ? NO_EXACT_CONSTANT_MATCHING_ICON : EXACT_CONSTANT_MATCHING_ICON);
			super.setSelected(selected);
		}
	}
}
