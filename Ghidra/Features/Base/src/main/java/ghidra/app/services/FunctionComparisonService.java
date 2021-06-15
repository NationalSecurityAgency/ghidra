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

import java.util.Set;

import docking.ComponentProviderActivationListener;
import ghidra.app.plugin.core.functioncompare.FunctionComparisonPlugin;
import ghidra.app.plugin.core.functioncompare.FunctionComparisonProvider;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.listing.Function;

/**
 * Allows users to create comparisons between functions which will be displayed
 * side-by-side in a {@link FunctionComparisonProvider}. Each side in the 
 * display will allow the user to select one or more functions 
 * 
 * <p>Concurrent usage: All work performed by this service will be done on the Swing thread.  
 * Further, all calls that do not return a value will be run immediately if the caller is on 
 * the Swing thread; otherwise, the work will be done on the Swing thread at a later time.  
 * Contrastingly, any method on this interface that returns a value will be run immediately,
 * regardless of whether the call is on the Swing thread.  Thus, the methods that return a value
 * will always be blocking calls; methods that do not return a value may or may not block, 
 * depending on the client's thread.
 */
@ServiceInfo(defaultProvider = FunctionComparisonPlugin.class)
public interface FunctionComparisonService {

	/**
	 * Creates a comparison between a set of functions, where each function
	 * in the list can be compared against any other.
	 * <p>
	 * eg: Given a set of 3 functions (f1, f2, f3), the comparison dialog will
	 * allow the user to display either f1, f2 or f3 on EITHER side of the
	 * comparison.
	 * <p>
	 * Note that this method will always create a new provider; if you want to 
	 * add functions to an existing comparison, use
	 * {@link #compareFunctions(Set, FunctionComparisonProvider) this}
	 * variant that takes a provider.
	 * 
	 * @param functions the functions to compare
	 * @return the new comparison provider 
	 */
	public FunctionComparisonProvider compareFunctions(Set<Function> functions);

	/**
	 * Creates a comparison between two functions, where the source function
	 * will be shown on the left side of the comparison dialog and the target 
	 * on the right. 
	 * <p>
	 * Note that this will always create a new provider; if you want to add 
	 * functions to an existing comparison, use 
	 * {@link #compareFunctions(Function, Function, FunctionComparisonProvider) this}
	 * variant that takes a provider.
	 * 
	 * @param source a function in the comparison
	 * @param target a function in the comparison
	 * @return the new comparison provider
	 */
	public FunctionComparisonProvider compareFunctions(Function source, Function target);

	/**
	 * Creates a comparison between a set of functions, adding them to the 
	 * given comparison provider. Each function in the given set will be added 
	 * to both sides of the comparison, allowing users to compare any functions
	 * in the existing provider with the new set.
	 * 
	 * @see #compareFunctions(Set)
	 * @param functions the functions to compare
	 * @param provider the provider to add the comparisons to
	 */
	public void compareFunctions(Set<Function> functions,
			FunctionComparisonProvider provider);

	/**
	 * Creates a comparison between two functions and adds it to a given
	 * comparison provider. The existing comparisons in the provider will not
	 * be affected, unless the provider already contains a comparison with 
	 * the same source function; in this case the given target will be added
	 * to that comparisons' list of targets.
	 * 
	 * @see #compareFunctions(Function, Function)
	 * @param source a function in the comparison
	 * @param target a function in the comparison
	 * @param provider the provider to add the comparison to
	 */
	public void compareFunctions(Function source, Function target,
			FunctionComparisonProvider provider);

	/**
	 * Removes a given function from all comparisons across all comparison 
	 * providers
	 * 
	 * @param function the function to remove
	 */
	public void removeFunction(Function function);

	/**
	 * Removes a given function from all comparisons in the given comparison
	 * provider only
	 * 
	 * @param function the function to remove
	 * @param provider the comparison provider to remove functions from
	 */
	public void removeFunction(Function function, FunctionComparisonProvider provider);

	/**
	 * Adds the given listener to the list of subscribers who wish to be 
	 * notified of provider activation events (eg: provider open/close)
	 * 
	 * @param listener the listener to be added
	 */
	public void addFunctionComparisonProviderListener(ComponentProviderActivationListener listener);

	/**
	 * Removes a listener from the list of provider activation event subscribers
	 * 
	 * @param listener the listener to remove
	 */
	public void removeFunctionComparisonProviderListener(
			ComponentProviderActivationListener listener);
}
