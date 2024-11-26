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
/**
 * 
 */
package ghidra.features.base.codecompare.model;

import java.util.Collection;
import java.util.List;

import ghidra.app.services.FunctionComparisonService;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Duo.Side;

/**
 * A model for comparing one or more functions in a side by side display. The model supports the
 * concept of a set of functions that can be selected for each side of the comparison. It also 
 * maintains the selected function for each side. The default model simply has a single set
 * of functions that can be selected for either side of the comparison. The model supports the
 * concept of different sets of functions for each and even the idea that the active function for
 * one side can determine the set of functions for the other side. See 
 * {@link MatchedFunctionComparisonModel}.
 * <p>
 * This model is intended to be used by the {@link FunctionComparisonService} to generate
 * a function comparison display window. 
 * <p>
 * Note: Subscribers may register to be informed of changes to this model via the
 * {@link FunctionComparisonModelListener comparison model listener} interface.
 */
public interface FunctionComparisonModel {

	/**
	 * Adds the given listener to the list of those to be notified of model changes.
	 * 
	 * @param listener the listener to add
	 */
	public void addFunctionComparisonModelListener(FunctionComparisonModelListener listener);

	/**
	 * Removes the given listener from the list of those to be notified of model changes.
	 * 
	 * @param listener the listener to remove
	 */
	public void removeFunctionComparisonModelListener(FunctionComparisonModelListener listener);

	/**
	 * Sets the function for the given side. The function must be one of the functions from that
	 * side's set of functions
	 * @param side the side to set the function for
	 * @param function the function so set for the given side
	 * @return true if the function was made active or false if the function does not exist for the
	 * given side
	 */
	public boolean setActiveFunction(Side side, Function function);

	/**
	 * Returns the active (selected) function for the given side.
	 * @param side the side to get the active function for
	 * @return the active function for the given side
	 */
	public Function getActiveFunction(Side side);

	/**
	 * Returns the list of all functions on the given side that could be made active.
	 * @param side the side to get functions for
	 * @return the list of all functions on the given side that could be made active
	 */
	public List<Function> getFunctions(Side side);

	/**
	 * Removes the given function from both sides of the comparison.
	 * 
	 * @param function the function to remove
	 */
	public void removeFunction(Function function);

	/**
	 * Removes all the given functions from both sides of the comparison.
	 * 
	 * @param functions the functions to remove
	 */
	public void removeFunctions(Collection<Function> functions);

	/**
	 * Removes all functions from the given program from both sides of the comparison
	 * @param program that program whose functions should be removed from this model
	 */
	public void removeFunctions(Program program);

	/**
	 * Returns true if the model has no function to compare. 
	 * @return true if the model has no functions to compare
	 */
	public boolean isEmpty();

}
