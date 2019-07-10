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

import java.util.*;

import javax.swing.DefaultComboBoxModel;

import docking.ComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.util.HelpLocation;

/**
 * Creates a panel for comparing two or more functions. One or more functions can be displayed
 * in the left side of the panel. Each of these left functions is mapped to its own set of functions,
 * which can be displayed one at a time in the right side of the panel for comparison.
 * If there are multiple functions to display within either the left or right side of this panel,
 * then a combo box will appear above the left and right side of the CodeComparisonPanels. 
 * Each combo box will allow the user to choose which function to display on that side of the panel.
 * Changing the selected function in the left side of the panel will possibly change the available
 * functions for display in the right side of the panel.
 */
public class MappedFunctionComparisonPanel extends FunctionChoiceComparisonPanel {

	private HashMap<Function, HashSet<Function>> functionMap;

	/**
	 * Constructor
	 * 
	 * @param provider the provider displaying this panel.
	 * @param tool the tool displaying this panel.
	 * @param functionMap map of the functions that are used to populate both the left and right side
	 * of the function comparison panel.
	 */
	public MappedFunctionComparisonPanel(ComponentProvider provider, PluginTool tool,
			HashMap<Function, HashSet<Function>> functionMap) {
		super(provider, tool, null, null);
		this.functionMap = functionMap;

		establishLeftFunctions(0);
		establishRightFunctions(0);

		if (leftWrappedFunctions.length > 1 || rightWrappedFunctions.length > 1) {
			addChoicePanel();
		}

		reloadLeftFunctions();
		reloadRightFunctions();

		createActions();
		help.registerHelp(this, new HelpLocation(HELP_TOPIC, "Function Comparison"));
	}

	/**
	 * Sets the left functions that are used in the left combo box for the left side of the 
	 * function comparison. These functions are in sorted order. It also sets the current 
	 * left index to a valid value that indicates which function in the left list is currently 
	 * selected.
	 * @param leftFunctionIndex the desired index of the left function that should be 
	 * selected currently. If the specified index isn't valid for the current list of left 
	 * functions then the left index will get set to 0 which indicates the first function.
	 */
	private void establishLeftFunctions(int leftFunctionIndex) {
		Set<Function> leftFunctionSet = functionMap.keySet();
		Function[] leftSortedFunctions = getSortedFunctions(leftFunctionSet);
		leftWrappedFunctions = getWrappedFunctions(leftSortedFunctions);
		leftIndex = (leftFunctionIndex < leftSortedFunctions.length) ? leftFunctionIndex : 0;
		setLeftFunction(leftSortedFunctions[leftIndex]);
	}

	private void adjustRightFunctions(int rightFunctionIndex) {
		establishRightFunctions(rightFunctionIndex);
		reloadRightFunctions();
	}

	/**
	 * Sets the right functions that are used in the right combo box for the right side of the 
	 * function comparison. These functions are in sorted order. It also sets the current 
	 * right index to a valid value that indicates which function in the right list is currently 
	 * selected.
	 * @param rightFunctionIndex the desired index of the right function that should be 
	 * selected currently. If the specified index isn't valid for the current list of right 
	 * functions then the right index will get set to 0 which indicates the first function.
	 */
	private void establishRightFunctions(int rightFunctionIndex) {
		Set<Function> rightFunctionSet = functionMap.get(getLeftFunction());
		Function[] rightSortedFunctions =
			(rightFunctionSet != null) ? getSortedFunctions(rightFunctionSet) : new Function[0];
		rightWrappedFunctions = getWrappedFunctions(rightSortedFunctions);
		rightIndex = (rightFunctionIndex < rightSortedFunctions.length) ? rightFunctionIndex : 0;
	}

	private void reloadLeftFunctions() {
		// Adjust the index if it is out of bounds.
		if (leftIndex >= leftWrappedFunctions.length) {
			leftIndex = 0;
		}
		if (leftComboBox != null) {
			// Load the functions into the combo box.
			leftComboBox.setModel(new DefaultComboBoxModel<>(leftWrappedFunctions));
			// Select the function in the combo box.
			adjustSelectedLeftFunction();
		}
		// Set the function in the view.
		Function leftFunctionAtIndex = (leftIndex < leftWrappedFunctions.length)
				? leftWrappedFunctions[leftIndex].getFunction()
				: null;
		setLeftFunction(leftFunctionAtIndex);
	}

	private void reloadRightFunctions() {
		// Adjust the index if it is out of bounds.
		if (rightIndex >= rightWrappedFunctions.length) {
			rightIndex = 0;
		}
		if (rightComboBox != null) {
			// Load the functions into the combo box.
			rightComboBox.setModel(new DefaultComboBoxModel<>(rightWrappedFunctions));
			// Select the function in the combo box.
			adjustSelectedRightFunction();
		}
		// Set the function in the view.
		Function rightFunctionAtIndex = (rightIndex < rightWrappedFunctions.length)
				? rightWrappedFunctions[rightIndex].getFunction()
				: null;
		setRightFunction(rightFunctionAtIndex);
	}

	/**
	 * Determines if the map of left functions to lists of associated right functions match 
	 * the map of functions currently displayed for comparison in the left and right side of 
	 * this panel.
	 * 
	 * @param functionMap the map of left functions to lists of right functions
	 * @return true if the map matches what is currently displayed by this panel.
	 */
	boolean matchesTheseFunctions(HashMap<Function, HashSet<Function>> myFunctionMap) {
		return functionMap.equals(myFunctionMap);
	}

	@Override
	public void loadFunctions(Function newLeftFunction, Function newRightFunction) {
		Function myLeftFunction = getLeftFunction();

		super.loadFunctions(newLeftFunction, newRightFunction);

		if (myLeftFunction != getLeftFunction()) {
			// Left function changed so adjust the function list in the right side.
			adjustRightFunctions(0);
		}
	}

}
