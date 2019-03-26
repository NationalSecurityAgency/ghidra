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

import java.io.Serializable;

/**
 * Simple holder object for an owner string and name string.
 */
class ComponentTransferableData implements Serializable {
	String owner;
	String name;
	/**
	 * Constructs a new CompProv object to be used in a drag/drop operation.
	 * @param dockComp the dockableComponent to used for the owner and name.
	 */
	ComponentTransferableData(DockableComponent dockComp) {
		ComponentPlaceholder info = dockComp.getComponentWindowingPlaceholder();
		this.owner = info.getOwner();
		this.name = info.getName();
	}

}
