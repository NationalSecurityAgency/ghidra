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
package docking.action;

import java.awt.Component;

import docking.ActionContext;
import docking.ComponentProvider;

/**
 * An interface to signal that the implementing action works with an individual Java 
 * {@link Component}.   Standard Docking Actions are either global tool-based actions or local 
 * {@link ComponentProvider} actions.   This interface allows us to have the concept of an 
 * action that is effectively local to a specific Java component.
 */
public interface ComponentBasedDockingAction extends DockingActionIf {

	/**
	 * Returns true if the given context contains this action's component
	 * @param context the context
	 * @return true if the given context contains this action's component
	 */
	public boolean isValidComponentContext(ActionContext context);
}
