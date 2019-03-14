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
package ghidra.app.services;

import ghidra.program.util.MarkerLocation;
import ghidra.program.util.ProgramLocation;

import javax.swing.ImageIcon;

/**
 * Listener for MarkerManager's created from the MarkerService.
 * It is called for navigation to the marker or to get a tooltip
 * for a marker.
 * 
 * 
 *
 */

public interface MarkerListener {
	/**
	 * Called when the navigation bar to the right of the window is selected to 
	 * allow the the creator of a Marker an opportunity to provide a more specific
	 * ProgramLocation to navigate to - otherwise the browser will navigate to
	 * the corresponding AddressLocation.
	 */
	public ProgramLocation getProgramLocation(MarkerLocation loc);
	
	/**
	 * Called to get a tool tip for a marker under the cursor in the marker panel
	 * to the left of the browser.
	 */
	public String getTooltip(MarkerLocation loc);
	
	/**
	 * Called to get the icon that corresponds to the given location.
	 */
	public ImageIcon getIcon(MarkerLocation loc);
}
