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
import java.awt.event.InputEvent;
import java.util.*;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.*;
import docking.help.Help;
import docking.help.HelpService;
import docking.widgets.combobox.GComboBox;
import docking.widgets.fieldpanel.internal.FieldPanelCoordinator;
import ghidra.app.util.viewer.util.CodeComparisonPanel;
import ghidra.app.util.viewer.util.CodeComparisonPanelActionContext;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.TranslateIcon;

/**
 * Creates a panel for comparing two or more functions.
 * If there are multiple functions to display within either the left or right side of this panel,
 * then a combo box will appear above the left and right side of the {@link CodeComparisonPanel}s. 
 * Each combo box will allow the user to choose which function to display on that side of the panel.
 */
public abstract class FunctionChoiceComparisonPanel extends FunctionComparisonPanel {

	private JPanel choicePanel; // null if only 1 left function and 1 right function.
	protected WrappedFunction[] leftWrappedFunctions = new WrappedFunction[] {};
	protected WrappedFunction[] rightWrappedFunctions = new WrappedFunction[] {};
	protected int leftIndex = 0;
	protected int rightIndex = 0;
	protected JComboBox<WrappedFunction> leftComboBox;
	protected JComboBox<WrappedFunction> rightComboBox;
	private NextFunctionAction nextFunctionAction;
	private PreviousFunctionAction previousFunctionAction;
	private static final String FUNCTION_NAVIGATE_GROUP = "A9_FunctionNavigate";
	private static final Icon FUNCTION_ICON =
		new TranslateIcon(ResourceManager.loadImage("images/FunctionScope.gif"), -5, -2);
	private static final Icon NEXT_ICON =
		new TranslateIcon(ResourceManager.loadImage("images/arrow_down.png"), 3, 1);
	private static final Icon PREVIOUS_ICON =
		new TranslateIcon(ResourceManager.loadImage("images/arrow_up.png"), 3, 1);
	private static final Icon NEXT_FUNCTION_ICON = new MultiIcon(NEXT_ICON, FUNCTION_ICON);
	private static final Icon PREVIOUS_FUNCTION_ICON = new MultiIcon(PREVIOUS_ICON, FUNCTION_ICON);
	protected static final HelpService help = Help.getHelpService();
	protected static final String HELP_TOPIC = "FunctionComparison";
	private MyFunctionComparator myFunctionComparator = new MyFunctionComparator();

	/**
	 * Creates a panel for comparing two or more functions.
	 *
	 * @param provider the GUI provider that includes this panel.
	 * @param tool the tool containing this panel
	 * @param leftFunction the function displayed in the left side of the panel.
	 * @param rightFunction the function displayed in the right side of the panel.
	 */
	protected FunctionChoiceComparisonPanel(ComponentProvider provider, PluginTool tool,
			Function leftFunction, Function rightFunction) {
		super(provider, tool, leftFunction, rightFunction);
	}

	/**
	 * Gets the functions for the left side of the panel.
	 * <br>
	 * These functions are sorted ascending on program and function name.
	 * The primary sort is on program including pathname. 
	 * The secondary sort is on function including namespace.
	 * 
	 * @return the functions that can be displayed on the left side.
	 */
	public Function[] getLeftFunctions() {
		Function[] leftFunctions = new Function[leftWrappedFunctions.length];
		for (int i = 0; i < leftWrappedFunctions.length; i++) {
			leftFunctions[i] = leftWrappedFunctions[i].getFunction();
		}
		return leftFunctions;
	}

	/**
	 * Gets the functions for the right side of the panel.
	 * <br>
	 * These functions are sorted ascending on program and function name.
	 * The primary sort is on program including pathname. 
	 * The secondary sort is on function including namespace.
	 * 
	 * @return the functions that can be displayed on the right side.
	 */
	public Function[] getRightFunctions() {
		Function[] rightFunctions = new Function[rightWrappedFunctions.length];
		for (int i = 0; i < rightWrappedFunctions.length; i++) {
			rightFunctions[i] = rightWrappedFunctions[i].getFunction();
		}
		return rightFunctions;
	}

	/**
	 * Gets an array of WrappedFunctions for the array of functions passed as a parameter.
	 * @param functionArray the functions to convert to WrappedFunctions.
	 * @return the WrappedFunctions.
	 */
	protected WrappedFunction[] getWrappedFunctions(Function[] functionArray) {
		WrappedFunction[] wrappedFunctionArray = new WrappedFunction[functionArray.length];
		for (int i = 0; i < functionArray.length; i++) {
			wrappedFunctionArray[i] = new WrappedFunction(functionArray[i]);
		}
		return wrappedFunctionArray;
	}

	/**
	 * Adds a panel with combo boxes for choosing the currently displayed function in the 
	 * left and right panel.  This also populates the combo boxes with the functions.
	 */
	protected void addChoicePanel() {
		choicePanel = new JPanel(new GridLayout(1, 2));
		choicePanel.add(createLeftChoicePanel());
		choicePanel.add(createRightChoicePanel());
		add(choicePanel, BorderLayout.NORTH);

		help.registerHelp(choicePanel, new HelpLocation(HELP_TOPIC, "Compare Multiple Functions"));
	}

	/**
	 * Updates the selected left function in the combo box based on the current left index.
	 */
	protected void adjustSelectedLeftFunction() {
		WrappedFunction leftWrappedFunction =
			(leftIndex < leftWrappedFunctions.length) ? leftWrappedFunctions[leftIndex] : null;
		leftComboBox.setSelectedItem(leftWrappedFunction);
	}

	/**
	 * Updates the selected right function in the combo box based on the current right index.
	 */
	protected void adjustSelectedRightFunction() {
		WrappedFunction rightWrappedFunction =
			(rightIndex < rightWrappedFunctions.length) ? rightWrappedFunctions[rightIndex] : null;
		rightComboBox.setSelectedItem(rightWrappedFunction);
	}

	private Component createLeftChoicePanel() {
		JPanel panel = new JPanel(new BorderLayout());
		leftComboBox = new GComboBox<>(leftWrappedFunctions);
		adjustSelectedLeftFunction();
		leftComboBox.addItemListener(e -> {
			WrappedFunction wrappedFunction = (WrappedFunction) leftComboBox.getSelectedItem();
			Function function = (wrappedFunction != null) ? wrappedFunction.getFunction() : null;
			setLeftFunction(function);
		});
		panel.add(leftComboBox, BorderLayout.CENTER);
		return panel;
	}

	private Component createRightChoicePanel() {
		JPanel panel = new JPanel(new BorderLayout());
		rightComboBox = new GComboBox<>(rightWrappedFunctions);
		adjustSelectedRightFunction();
		rightComboBox.addItemListener(e -> {
			WrappedFunction wrappedFunction = (WrappedFunction) rightComboBox.getSelectedItem();
			Function function = (wrappedFunction != null) ? wrappedFunction.getFunction() : null;
			setRightFunction(function);
		});
		panel.add(rightComboBox, BorderLayout.CENTER);
		return panel;
	}

	/**
	 * Creates actions for displaying the next or previous function if we are using combo boxes.
	 */
	protected void createActions() {
		if (choicePanel != null) {
			nextFunctionAction = new NextFunctionAction();
			previousFunctionAction = new PreviousFunctionAction();
		}
	}

	@Override
	public DockingAction[] getCodeComparisonActions() {
		DockingAction[] otherActions = super.getCodeComparisonActions();
		if (choicePanel == null) {
			return otherActions;
		}
		DockingAction[] myActions =
			new DockingAction[] { nextFunctionAction, previousFunctionAction };
		DockingAction[] actions = new DockingAction[otherActions.length + myActions.length];
		System.arraycopy(otherActions, 0, actions, 0, otherActions.length);
		System.arraycopy(myActions, 0, actions, otherActions.length, myActions.length);
		return actions;
	}

	private boolean isValidPanelContext(ActionContext context) {
		if (context instanceof CodeComparisonPanelActionContext) {
			return choicePanel != null;
		}
		return false;
	}

	private void nextFunction() {
		CodeComparisonPanel<? extends FieldPanelCoordinator> currentComponent =
			getCurrentComponent();
		if (currentComponent == null) {
			return;
		}
		boolean leftHasFocus = currentComponent.leftPanelHasFocus();
		if (leftHasFocus) {
			if (leftIndex < (leftWrappedFunctions.length - 1)) {
				leftComboBox.setSelectedIndex(++leftIndex);
			}
			else {
				outputNoNextPreviousMessage(true, leftHasFocus);
				return;
			}
		}
		else { // right has focus.
			if (rightIndex < (rightWrappedFunctions.length - 1)) {
				rightComboBox.setSelectedIndex(++rightIndex);
			}
			else {
				outputNoNextPreviousMessage(true, leftHasFocus);
				return;
			}
		}
	}

	private void previousFunction() {
		CodeComparisonPanel<? extends FieldPanelCoordinator> currentComponent =
			getCurrentComponent();
		if (currentComponent == null) {
			return;
		}
		boolean leftHasFocus = currentComponent.leftPanelHasFocus();
		if (leftHasFocus) {
			if (leftIndex > 0) {
				leftComboBox.setSelectedIndex(--leftIndex);
			}
			else {
				outputNoNextPreviousMessage(false, leftHasFocus);
				return;
			}
		}
		else { // right has focus.
			if (rightIndex > 0) {
				rightComboBox.setSelectedIndex(--rightIndex);
			}
			else {
				outputNoNextPreviousMessage(false, leftHasFocus);
				return;
			}
		}
	}

	private void outputNoNextPreviousMessage(boolean forward, boolean isFirstListing) {
		tool.setStatusInfo("There isn't another " + (forward ? "next " : "previous ") +
			"function for the " + (isFirstListing ? "first" : "second") + " listing.");
	}

	/**
	 * Action to display the next function in the currently focused side of the function
	 * comparison panel if possible.
	 */
	protected class NextFunctionAction extends DockingAction {

		NextFunctionAction() {
			super("Compare Next Function", provider.getOwner());
			setKeyBindingData(
				new KeyBindingData('N', InputEvent.CTRL_MASK | InputEvent.SHIFT_MASK));
			setDescription("Compare the next function for the side with focus.");
			setPopupMenuData(new MenuData(new String[] { "Compare The Next Function" },
				NEXT_FUNCTION_ICON, FUNCTION_NAVIGATE_GROUP));
			ToolBarData newToolBarData =
				new ToolBarData(NEXT_FUNCTION_ICON, FUNCTION_NAVIGATE_GROUP);
			setToolBarData(newToolBarData);

			HelpLocation helpLocation = new HelpLocation(HELP_TOPIC, "Compare The Next Function");
			setHelpLocation(helpLocation);
			setEnabled(true);
		}

		@Override
		public boolean isValidContext(ActionContext context) {
			return isValidPanelContext(context);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (isValidContext(context)) {
				nextFunction();
			}
		}
	}

	/**
	 * Action to display the previous function in the currently focused side of the function
	 * comparison panel if possible.
	 */
	protected class PreviousFunctionAction extends DockingAction {

		PreviousFunctionAction() {
			super("Compare Previous Function", provider.getOwner());
			setKeyBindingData(
				new KeyBindingData('P', InputEvent.CTRL_MASK | InputEvent.SHIFT_MASK));
			setDescription("Compare the previous function for the side with focus.");
			setPopupMenuData(new MenuData(new String[] { "Compare The Previous Function" },
				PREVIOUS_FUNCTION_ICON, FUNCTION_NAVIGATE_GROUP));
			ToolBarData newToolBarData =
				new ToolBarData(PREVIOUS_FUNCTION_ICON, FUNCTION_NAVIGATE_GROUP);
			setToolBarData(newToolBarData);

			HelpLocation helpLocation =
				new HelpLocation(HELP_TOPIC, "Compare The Previous Function");
			setHelpLocation(helpLocation);
			setEnabled(true);
		}

		@Override
		public boolean isValidContext(ActionContext context) {
			return isValidPanelContext(context);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (isValidContext(context)) {
				previousFunction();
			}
		}
	}

	/**
	 * Gets a sorted array of the functions for the indicated set of functions.
	 * This sorts the functions first by program and then by function name. 
	 * The primary sort is ascending on the program's pathname. 
	 * The secondary sort is ascending on the function's name which includes its namespace.
	 * 
	 * @param functions the set of functions
	 * @return the sorted array of functions
	 */
	protected Function[] getSortedFunctions(Set<Function> functions) {
		Function[] sortedFunctions = functions.toArray(new Function[functions.size()]);
		Arrays.sort(sortedFunctions, myFunctionComparator);
		return sortedFunctions;
	}

	/**
	 * Gets a sorted array of the functions for the indicated array of functions.
	 * This sorts the functions first by program and then by function name. 
	 * The primary sort is ascending on the program's pathname. 
	 * The secondary sort is ascending on the function's name which includes its namespace.
	 * <br>
	 * The original function array is not modified.
	 * 
	 * @param functions the array of functions
	 * @return a new sorted array of functions
	 */
	protected Function[] getSortedFunctions(Function[] functions) {
		Function[] sortedFunctions = Arrays.copyOf(functions, functions.length);
		Arrays.sort(sortedFunctions, myFunctionComparator);
		return sortedFunctions;
	}

	/**
	 * A comparator for functions that sorts the functions first by program and then by
	 * function name. 
	 * The primary sort is ascending on the program's pathname. 
	 * The secondary sort is ascending on the function's name which includes its namespace.
	 */
	private class MyFunctionComparator implements Comparator<Function> {

		@Override
		public int compare(Function function1, Function function2) {
			if (function1 == null) {
				if (function2 == null) {
					return 0;
				}
				return -1;
			}
			if (function1 == function2) {
				return 0;
			}
			String function1Name = function1.getName(true);
			String function2Name = function2.getName(true);

			Program program1 = function1.getProgram();
			Program program2 = function2.getProgram();

			String program1Name = program1.getDomainFile().getPathname();
			String program2Name = program2.getDomainFile().getPathname();

			int comparePrograms = program1Name.compareTo(program2Name);
			if (comparePrograms != 0) {
				return comparePrograms;
			}

			return function1Name.compareTo(function2Name);
		}
	}

	/**
	 * Class that allows us to display a more informative string in the combo box for each function.
	 */
	protected static class WrappedFunction {

		private Function function;

		private WrappedFunction(Function function) {
			this.function = function;
		}

		protected Function getFunction() {
			return function;
		}

		@Override
		public String toString() {
			return getFunctionTitle();
		}

		private String getFunctionTitle() {
			if (function == null) {
				return "none";
			}
			Program program = function.getProgram();
			return function.getName(true) + "()" +
				((program != null) ? (" in " + program.getDomainFile().getPathname() + "") : "");
		}
	}
}
