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

import javax.swing.ImageIcon;

import ghidra.program.util.MarkerLocation;
import ghidra.program.util.ProgramLocation;

/**
 * Allows clients to specify how {@link MarkerLocation}s are navigated, as well as how they 
 * should be painted
 */
public abstract class MarkerDescriptor {

	/**
	 * Called when the navigation bar to the right of the window is clicked to allow the the 
	 * creator of a Marker an opportunity to provide a more specific ProgramLocation for
	 * navigation. If null is specified, the client will navigate to the corresponding address.
	 * @param loc the marker location
	 * @return the desired location; may be null
	 */
	public ProgramLocation getProgramLocation(MarkerLocation loc) {
		return null;
	}

	/**
	 * Called to get a tool tip for a marker under the cursor in the marker panel 
	 * @param loc the marker location
	 * @return the tooltip; may be null
	 */
	public String getTooltip(MarkerLocation loc) {
		return null;
	}

	/**
	 * Called to get the icon that corresponds to the given location
	 * @param loc the marker location
	 * @return the icon; may be null
	 */
	public ImageIcon getIcon(MarkerLocation loc) {
		return null;
	}
}
