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
package ghidra.app.services;

import java.util.Collection;

import ghidra.features.base.codecompare.model.FunctionComparisonModel;
import ghidra.features.base.codecompare.model.MatchedFunctionComparisonModel;
import ghidra.program.model.listing.Function;
import utility.function.Callback;

/**
 * Service interface to create comparisons between functions which will be displayed
 * side-by-side in a function comparison window. Each side in the 
 * display will allow the user to select one or more functions 
 * 
 * <p>Concurrent usage: All work performed by this service will be done asynchronously on the
 * Swing thread.  
 */
public interface FunctionComparisonService {

	/**
	 * Creates a function comparison window where each side can display any of the given functions.
	 * @param functions the functions to compare
	 */
	public void createComparison(Collection<Function> functions);

	/**
	 * Creates a function comparison window for the two given functions. Each side can select
	 * either function, but initially the left function will be shown in the left panel and the
	 * right function will be shown in the right panel.
	 * @param left the function to initially show in the left panel
	 * @param right the function to initially show in the right panel
	 */
	public void createComparison(Function left, Function right);

	/**
	 * Adds the given function to each side the last created comparison window or creates
	 * a new comparison if none exists. The right panel will be changed to show the new function.
	 * Note that this method will not add to any provider created via the
	 * {@link #createCustomComparison(FunctionComparisonModel, Callback)}. Those providers
	 * are private to the client that created them. They take in a model, so if the client wants
	 * to add to those providers, it must retain a handle to the model and add functions directly
	 * to the model.
	 * @param function the function to be added to the last function comparison window
	 */
	public void addToComparison(Function function);

	/**
	 * Adds the given functions to each side the last created comparison window or creates
	 * a new comparison if none exists. The right panel will be change to show a random function
	 * from the new functions. Note that this method will not add to any comparison windows created
	 * with a custom comparison model.
	 * @param functions the functions to be added to the last function comparison window
	 */
	public void addToComparison(Collection<Function> functions);

	/**
	 * Creates a custom function comparison window. The default model shows all functions on both
	 * sides. This method allows the client to provide a custom comparison model which can have
	 * more control over what functions can be selected on each side. One such custom model
	 * is the {@link MatchedFunctionComparisonModel} which gives a unique set of functions on the
	 * right side, depending on what is selected on the left side.
	 * <P>
	 * Note that function comparison windows created with this method are considered private for the
	 * client and are not available to be chosen for either of the above "add to" service methods. 
	 * Instead, the client that uses this model can retain a handle to the model and add or remove
	 * functions directly on the model.
	 *
	 * @param model the custom function comparison model
	 * @param closeListener an optional callback if the client wants to be notified when the 
	 * associated function comparison windows is closed.
	 */
	public void createCustomComparison(FunctionComparisonModel model,
			Callback closeListener);
}
