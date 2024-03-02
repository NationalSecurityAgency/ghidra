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
package ghidra.codecompare;

import java.util.List;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import docking.action.ToolBarData;
import generic.theme.GIcon;
import ghidra.app.decompiler.component.DecompileData;
import ghidra.app.decompiler.component.DecompilerCodeComparisonPanel;
import ghidra.app.decompiler.component.DualDecompileResultsListener;
import ghidra.app.decompiler.component.DualDecompilerActionContext;
import ghidra.codecompare.graphanalysis.TokenBin;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskBuilder;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskListener;
import resources.Icons;
import resources.MultiIcon;

/**
 * This is a CodeComparisonPanel that gets discovered by other providers that display dual 
 * comparison views.<br>
 * Note: Therefore there may not be any other classes that refer directly to it.
 */
public class DecompilerDiffCodeComparisonPanel
		extends DecompilerCodeComparisonPanel<CodeDiffFieldPanelCoordinator>
		implements DualDecompileResultsListener, OptionsChangeListener {

	public static final String CODE_DIFF_VIEW = "Decompiler Diff View";
	private static final String HELP_TOPIC = "FunctionComparison";
	private DecompileDataDiff decompileDataDiff;
	private DiffClangHighlightController leftHighlightController;
	private DiffClangHighlightController rightHighlightController;
	private CodeDiffFieldPanelCoordinator decompilerFieldPanelCoordinator;
	private MyToggleExactConstantMatching toggleExactConstantMatchingAction;
	private boolean isMatchingConstantsExactly = true;
	private boolean toggleFlagWhenLastVisible = isMatchingConstantsExactly;
	private CompareFuncsFromMatchedTokensAction compareFuncsAction;
	private DecompilerCodeComparisonOptions comparisonOptions;

	/**
	 * Constructor
	 * @param owner owner
	 * @param tool tool
	 */
	public DecompilerDiffCodeComparisonPanel(String owner, PluginTool tool) {
		super(owner, tool);

		comparisonOptions = new DecompilerCodeComparisonOptions();
		initializeOptions();
		leftHighlightController = new DiffClangHighlightController(comparisonOptions);
		rightHighlightController = new DiffClangHighlightController(comparisonOptions);
		setHighlightControllers(leftHighlightController, rightHighlightController);

		// Make the left highlight listen to the right.
		leftHighlightController.addListener(rightHighlightController);
		// Make the right highlight listen to the left.
		rightHighlightController.addListener(leftHighlightController);

		addDualDecompileResultsListener(this);
		decompilerFieldPanelCoordinator = new CodeDiffFieldPanelCoordinator(this);
		setFieldPanelCoordinator(decompilerFieldPanelCoordinator);

	}

	private void initializeOptions() {
		ToolOptions options =
			tool.getOptions(DecompilerCodeComparisonOptions.OPTIONS_CATEGORY_NAME);
		options.addOptionsChangeListener(this);
		comparisonOptions.registerOptions(options);
		comparisonOptions.loadOptions(options);
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		comparisonOptions.loadOptions(options);
		repaint();
	}

	@Override
	public void setVisible(boolean aFlag) {
		if (aFlag == isVisible()) {
			return;
		}
		if (aFlag) {
			// Becoming visible.
			if (toggleFlagWhenLastVisible != isMatchingConstantsExactly) {
				if (decompileDataDiff != null) {
					determineDecompilerDifferences();
				}
			}
		}
		else {
			// No longer visible.
			toggleFlagWhenLastVisible = isMatchingConstantsExactly;
		}
		super.setVisible(aFlag);
		updateActionEnablement();
	}

	@Override
	public String getTitle() {
		return CODE_DIFF_VIEW;
	}

	@Override
	public void decompileResultsSet(DecompileData leftDecompileResults,
			DecompileData rightDecompileResults) {

		if ((leftDecompileResults == null) || (rightDecompileResults == null) ||
			(leftDecompileResults.getFunction() == null) ||
			(rightDecompileResults.getFunction() == null)) {
			return;
		}

		decompileDataDiff = new DecompileDataDiff(leftDecompileResults, rightDecompileResults);
		determineDecompilerDifferences();
	}

	List<TokenBin> getHighBins() {
		return decompilerFieldPanelCoordinator.getHighBins();
	}

	private void determineDecompilerDifferences() {
		if (decompileDataDiff == null) {
			return;
		}
		DetermineDecompilerDifferencesTask task =
			new DetermineDecompilerDifferencesTask(decompileDataDiff, isMatchingConstantsExactly,
				leftHighlightController, rightHighlightController, decompilerFieldPanelCoordinator);

		task.addTaskListener(new TaskListener() {

			@Override
			public void taskCompleted(Task completedTask) {
				// Does this need anything here?
			}

			@Override
			public void taskCancelled(Task cancelledTask) {
				// Does this need anything here?
			}
		});

		new TaskLauncher(task, getComponent());
	}

	@Override
	protected void createActions() {
		super.createActions();
		toggleExactConstantMatchingAction = new MyToggleExactConstantMatching(getClass().getName());
		compareFuncsAction = new CompareFuncsFromMatchedTokensAction(this, tool);
	}

	@Override
	public DockingAction[] getActions() {
		DockingAction[] parentActions = super.getActions();
		DockingAction[] myActions =
			new DockingAction[] { toggleExactConstantMatchingAction, compareFuncsAction };
		DockingAction[] allActions = new DockingAction[parentActions.length + myActions.length];
		System.arraycopy(parentActions, 0, allActions, 0, parentActions.length);
		System.arraycopy(myActions, 0, allActions, parentActions.length, myActions.length);
		return allActions;
	}

	@Override
	public void updateActionEnablement() {
		// Need to enable/disable toolbar button.
		toggleExactConstantMatchingAction.setEnabled(isVisible());
	}

	public class MyToggleExactConstantMatching extends ToggleDockingAction {

		private final Icon EXACT_CONSTANT_MATCHING_ICON = new GIcon("icon.base.source.c");
		private final Icon NO_EXACT_CONSTANT_MATCHING_ICON =
			new MultiIcon(EXACT_CONSTANT_MATCHING_ICON, Icons.NOT_ALLOWED_ICON);

		/**
		 * Creates an action for toggling exact constant matching in the code diff's 
		 * dual decompiler.
		 * @param owner the owner of this action (typically the provider).
		 */
		public MyToggleExactConstantMatching(String owner) {
			super("Toggle Exact Constant Matching", owner);
			setHelpLocation(new HelpLocation(HELP_TOPIC, "Toggle Exact Constant Matching"));
			
			this.setToolBarData(new ToolBarData(NO_EXACT_CONSTANT_MATCHING_ICON, "toggles"));

			setDescription(HTMLUtilities.toHTML("Toggle whether or not constants must\n" +
				"be exactly the same value to be a match\n" + "in the " + CODE_DIFF_VIEW + "."));
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
			isMatchingConstantsExactly = !isSelected();
			if (DecompilerDiffCodeComparisonPanel.this.isVisible()) {
				DecompilerDiffCodeComparisonPanel.this.determineDecompilerDifferences();
			}
		}

		@Override
		public void setSelected(boolean selected) {
			getToolBarData().setIcon(
				selected ? NO_EXACT_CONSTANT_MATCHING_ICON : EXACT_CONSTANT_MATCHING_ICON);
			super.setSelected(selected);
		}
	}

	@Override
	protected CodeDiffFieldPanelCoordinator createFieldPanelCoordinator() {
		CodeDiffFieldPanelCoordinator coordinator = new CodeDiffFieldPanelCoordinator(this);
		if (decompileDataDiff != null) {
			TaskBuilder.withRunnable(monitor -> {
				try {
					coordinator.replaceDecompileDataDiff(decompileDataDiff,
						isMatchingConstantsExactly, monitor);
				}
				catch (CancelledException e) {
					coordinator.clearLineNumberPairing();
				}
			}).setTitle("Initializing Code Compare").launchNonModal();
		}
		return coordinator;

	}
}
