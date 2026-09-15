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

import docking.ActionContext;
import ghidra.program.util.ProgramLocation;

/**
 * A "mix-in" interface that specific implementers of {@link ActionContext} may also implement if
 * they can supply a program location in their action context. Actions that want to work on 
 * locations can look for this interface, which can be used in a variety of contexts.
 */
public interface ProgramLocationSupplierContext extends ActionContext {

	/**
	 * {@return the program location}
	 */
	public ProgramLocation getLocation();
}
