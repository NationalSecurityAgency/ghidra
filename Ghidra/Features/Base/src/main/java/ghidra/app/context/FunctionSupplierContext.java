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
package ghidra.app.context;

import java.util.Set;

import docking.ActionContext;
import ghidra.program.model.listing.Function;

/**
 * A "mix-in" interface that specific implementers of {@link ActionContext} may also implement if
 * they can supply functions in their action context. Actions that want to work on functions
 * can look for this interface, which can used in a variety of contexts.
 */
public interface FunctionSupplierContext extends ActionContext {

	/**
	 * Returns true if this context can supply one or more functions. 
	 * @return true if this context can supply one or more functions
	 */
	public boolean hasFunctions();

	/**
	 * Returns the set of functions that this context object can supply.
	 * @return the set of functions that this context object can supply
	 */
	public Set<Function> getFunctions();
}
