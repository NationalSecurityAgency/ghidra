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
package docking;

import docking.action.DockingActionIf;

/**
 * A listener to be notified when the tool's context changes.   Normally context is used to 
 * manage {@link DockingActionIf} enablement directly by the system.  This class allows 
 * clients to listen to context change as well.
 */
public interface DockingContextListener {

	/**
	 * Called when the context changes
	 * @param context the context
	 */
	public void contextChanged(ActionContext context);
}
