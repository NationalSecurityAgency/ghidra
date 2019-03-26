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
package ghidra.app.events;

import ghidra.framework.plugintool.PluginEvent;
import ghidra.program.util.GroupPath;

/**
 * 
 * Notification for a new Program Tree selection.
 * 
 * 
 */
public final class TreeSelectionPluginEvent extends PluginEvent {
	/**
	 * Name of the event.
	 */
	public static final String NAME = "ProgramTreeSelection";
	
	private GroupPath[] groupPaths;
	private String treeName;
	
	/**
	 * Constructor for TreeSelectionPluginEvent.
	 * @param source name of the plugin that generated this event
	 * @param treeName name of the tree in the program
	 * @param groupPaths group paths that are selected in a Program Tree; the
	 * group path uniquely identifies a Module (folder) or fragment in the
	 * tree
	 */
	public TreeSelectionPluginEvent(String source, String treeName,
									GroupPath[] groupPaths) {
		super(source, NAME);
		this.treeName = treeName;
		this.groupPaths = groupPaths;
	}

	/**
	 * Get the group paths that are in the tree selection.
	 */
	public GroupPath[] getGroupPaths() {
		return groupPaths;
	}
	/**
	 * Get the tree name associated with this event.
	 * @return String tree name
	 */
	public String getTreeName() {
		return treeName;
	}
	/**
	 * String representation of this event for debugging purposes.
	 * @see java.lang.Object#toString()
	 */
	@Override
    public String toString() {
		StringBuffer sb = new StringBuffer("Tree Name = ");
		sb.append(treeName);
		sb.append(", Group Paths = {");
		for (int i=0; i<groupPaths.length; i++) {
			sb.append("[");
			sb.append(groupPaths[i].toString());
			sb.append("]");
			if (i < groupPaths.length - 1) {
				sb.append(", ");
			}
		}
		sb.append("}");
		return sb.toString();	
	}
}
