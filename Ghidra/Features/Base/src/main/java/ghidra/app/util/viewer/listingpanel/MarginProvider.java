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

import javax.swing.JComponent;

import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.program.model.listing.Program;
import ghidra.program.util.MarkerLocation;

/**
 * Interface for objects that want to add a component to the listing's left margin.
 */
public interface MarginProvider {

	/**
	 * Get the component to show the margin markers.
	 */
	JComponent getComponent();

	/**
	 * Return whether the component can be resized.
	 */
	boolean isResizeable();

	/**
	 * Set the program and associated maps.
	 * 
	 * @param program the program to use.
	 * @param addressIndexMap the address-index map to use.
	 * @param pixelMap the vertical pixel map to use.
	 */
	void setProgram(Program program, AddressIndexMap addressIndexMap,
			VerticalPixelAddressMap pixelMap);

	/**
	 * Get the marker location for the given x, y point.
	 * 
	 * @param x the horizontal coordinate.
	 * @param y the vertical coordinate.
	 */
	public MarkerLocation getMarkerLocation(int x, int y);

}
