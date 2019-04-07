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
package ghidra.app.util.viewer.listingpanel;

import ghidra.program.util.ProgramLocation;
import docking.widgets.fieldpanel.listener.ViewListener;

/**
 * Coordinates the locations between the left and right sides of a dual listing panel.
 */
public interface DualListingFieldPanelCoordinator extends ViewListener {

	/**
	 * Method that gets called when the location changes in the left side's program listing.
	 * @param leftLocation the new location in the left side.
	 */
	public void leftLocationChanged(ProgramLocation leftLocation);

	/**
	 * Method that gets called when the location changes in the right side's program listing.
	 * @param rightLocation the new location in the right side.
	 */
	public void rightLocationChanged(ProgramLocation rightLocation);
}
