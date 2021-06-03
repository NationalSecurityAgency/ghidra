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

import java.util.List;

import docking.Tool;

/**
 * An interface for objects (really Components) to implement that signals they provide actions 
 * for the Docking environment.  This interface will be called when the implementor is the source
 * of a Java event, like a MouseEvent.
 * <p>
 * As an example, a JTable that wishes to provide popup menu actions can implement this interface.
 * When the user right-clicks on said table, then Docking system will ask this object for its
 * actions.  Further, in this example, the actions given will be inserted into the popup menu
 * that is shown.
 * 
 * @deprecated use {@link Tool}
 */
// Note: this API is not likely used by forward-facing clients and can be removed in the next release
@Deprecated(since = "9.1", forRemoval = true)
public interface DockingActionProviderIf {

	/**
	 * Returns actions that are compatible with the given context.
	 * @return the actions
	 */
	public List<DockingActionIf> getDockingActions();
}
