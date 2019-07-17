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
import ghidra.program.model.address.AddressSet;

/**
 * Event for notifying plugins when the program view changes (what the
 * Code Browser shows in the listing window).
 */
public final class ViewChangedPluginEvent extends PluginEvent {
	/**
	 * Name of the event.
	 */
	public static final String NAME = "ViewChanged";
	
	private String treeName; // name of the tree for where the view is
							// coming from
	private AddressSet viewSet;
	
	/**
	 * Constructor for ViewChangedPluginEvent.
	 * @param source name of the plugin that created this event
	 * @param treeName name of the tree in the program
	 * @param viewSet set of addresses in the view
	 */
	public ViewChangedPluginEvent(String source, 
								  String treeName, AddressSet viewSet) {
		super(source, NAME);
		this.treeName = treeName;
		this.viewSet = viewSet;
	}

	/**
	 * Get the name of the tree where the view is from.
	 */
	public String getTreeName() {
		return treeName;
	}
	/**
	 * Get the address set in the view.
	 */
	public AddressSet getView() {
		return viewSet;
	}
	/**
	 * Returns a string for debugging purposes.
	 * @see java.lang.Object#toString()
	 */
	@Override
    public String toString() {
		return "Tree Name = " + treeName + 
				", AddressSet = " + viewSet;
	}
}
