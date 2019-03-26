/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package docking.widgets.tree.support;

import javax.swing.event.TreeSelectionEvent;
import javax.swing.tree.TreePath;

public class GTreeSelectionEvent {
	
	/**
	 * An enum that contains the origin of the GTreeSelectionEvent (see each enum for more 
	 * details).
	 */
	public enum EventOrigin {
		/** This event was triggered by an API on the GTree interface */
		API_GENERATED,
		
		/** This event was triggered by an internal GTree selection change (e.g., filter change) */
		INTERNAL_GENERATED,
		
		/** This event was triggered by the <b>user</b> changing the selection via the GUI */ 		
		USER_GENERATED
	}
	
	private final TreeSelectionEvent event;
	private final EventOrigin origin;

	public GTreeSelectionEvent( TreeSelectionEvent event, EventOrigin origin ) {
		this.event = event;
		this.origin = origin;
	}

	public EventOrigin getEventOrigin() {
		return origin;
	}
	
//==================================================================================================
// Event Delegate Methods	
//==================================================================================================
	
	public TreePath getNewLeadSelectionPath() {
		return event.getNewLeadSelectionPath();
	}

	public TreePath getOldLeadSelectionPath() {
		return event.getOldLeadSelectionPath();
	}

	public TreePath getPath() {
		return event.getPath();
	}

	public TreePath[] getPaths() {
		return event.getPaths();
	}

	public Object getSource() {
		return event.getSource();
	}

	public boolean isAddedPath() {
		return event.isAddedPath();
	}

	public boolean isAddedPath(int index) {
		return event.isAddedPath(index);
	}

	public boolean isAddedPath(TreePath path) {
		return event.isAddedPath(path);
	}
}
