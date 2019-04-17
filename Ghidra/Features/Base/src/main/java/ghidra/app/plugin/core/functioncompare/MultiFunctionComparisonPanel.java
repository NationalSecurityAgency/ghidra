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

import java.util.Arrays;

import docking.ComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.util.HelpLocation;

/**
 * Creates a panel for comparing two or more functions.
 * If there are multiple functions to display within either the left or right side of this panel,
 * then a combo box will appear above the left and right side of the CodeComparisonPanels. 
 * Each combo box will allow the user to choose which function to display on that side of the panel.
 */
public class MultiFunctionComparisonPanel extends FunctionChoiceComparisonPanel {

	/**
	 * Creates a panel for displaying two or more functions to be compared. This makes the 
	 * functions available for display in both the left side and right side of the panel after
	 * they are sorted ascending based on the program and function. The primary sort is on 
	 * program including pathname. The secondary sort is on function including namespace.
	 * By default the first function will be loaded into the left side and the second function 
	 * will be loaded in the right side.
	 * @param provider the provider displaying this panel.
	 * @param tool the tool displaying this panel.
	 * @param functions the functions that are used to populate both the left and right side
	 * of the function comparison panel.
	 */
	public MultiFunctionComparisonPanel(ComponentProvider provider, PluginTool tool,
			Function[] functions) {
		super(provider, tool, null, null);
		// For now, sort the functions.
		Function[] sortedFunctions = getSortedFunctions(functions);
		leftWrappedFunctions = getWrappedFunctions(sortedFunctions);
		rightWrappedFunctions = leftWrappedFunctions;
		if (leftWrappedFunctions.length >= 2) {
			Function leftFunction = (leftIndex < leftWrappedFunctions.length)
					? leftWrappedFunctions[leftIndex].getFunction()
					: null;
			++rightIndex;
			Function rightFunction = (rightIndex < rightWrappedFunctions.length)
					? rightWrappedFunctions[rightIndex].getFunction()
					: null;
			loadFunctions(leftFunction, rightFunction);
		}
		// Don't include the choice panel with its combo boxes unless there are more than 2 functions.
		if (leftWrappedFunctions.length > 2) {
			addChoicePanel(); // This also populates the combo boxes.
		}
		createActions();
		help.registerHelp(this, new HelpLocation(HELP_TOPIC, "Function Comparison"));
	}

	/**
	 * Creates a panel for displaying two or more functions to be compared. This will load the 
	 * functions so the leftFunctions are available for display in the left side and the 
	 * rightFunctions are available for display in the right side of the function comparison panel. 
	 * The functions are sorted ascending based on the program and function. The primary sort 
	 * is on program including pathname. The secondary sort is on function including namespace.
	 * By default the first function from each array will be the one initially displayed in its
	 * associated side.
	 * @param provider the provider displaying this panel.
	 * @param tool the tool displaying this panel.
	 * @param leftFunctions the functions that are used to populate the left side
	 * @param rightFunctions the functions that are used to populate the right side
	 */
	public MultiFunctionComparisonPanel(ComponentProvider provider, PluginTool tool,
			Function[] leftFunctions, Function[] rightFunctions) {
		super(provider, tool, null, null);
		Function[] sortedLeftFunctions = getSortedFunctions(leftFunctions);
		Function[] sortedRightFunctions = getSortedFunctions(rightFunctions);
		leftWrappedFunctions = getWrappedFunctions(sortedLeftFunctions);
		rightWrappedFunctions =
			Arrays.equals(sortedLeftFunctions, sortedRightFunctions) ? leftWrappedFunctions
					: getWrappedFunctions(sortedRightFunctions);
		if ((leftWrappedFunctions.length >= 1) && (rightWrappedFunctions.length >= 1)) {
			Function leftFunction = (leftIndex < leftWrappedFunctions.length)
					? leftWrappedFunctions[leftIndex].getFunction()
					: null; // Initially leftIndex is 0.
			Function rightFunction = (rightIndex < rightWrappedFunctions.length)
					? rightWrappedFunctions[rightIndex].getFunction()
					: null; // Initially rightIndex is 0.
			if (leftFunction == rightFunction && rightWrappedFunctions.length > 1) {
				rightFunction = rightWrappedFunctions[++rightIndex].getFunction();
			}
			loadFunctions(leftFunction, rightFunction);
		}
		if (leftWrappedFunctions.length > 1 || rightWrappedFunctions.length > 1) {
			addChoicePanel(); // This also populates the combo boxes.
		}
		createActions();
	}

	/**
	 * Determines if <code>functionsL</code> and <code>functionsR</code> match the functions 
	 * that can be displayed for comparison in the left and right side of this panel.
	 * 
	 * @param functionsL the functions to check against those used to populate the left side
	 * @param functionsR the functions to check against those used to populate the right side
	 * @return true if functionsL and functionsR match the functions that can be displayed by
	 * this panel.
	 */
	boolean matchesTheseFunctions(Function[] functionsL, Function[] functionsR) {
		return Arrays.equals(getLeftFunctions(), getSortedFunctions(functionsL)) &&
			Arrays.equals(getRightFunctions(), getSortedFunctions(functionsR));
	}
}
