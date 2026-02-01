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
import ghidra.program.util.MarkerLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.UniversalID;

/**
 * Interface for objects that want to add a component to the listing's left margin.
 */
public interface ListingMarginProvider {

	/**
	 * Sets the optional owner ID to be used with this margin provider.  Implementations may use 
	 * this ID to determine when they should paint.
	 * @param ownerId the ID
	 */

	/**
	 * Sets an optional owner ID that signals when the markers for this provider should be painted. 
	 * A null ID means that this provider is a non-snapshot provider and should paint all markers. 
	 * A non-null ID means this provider's markers will be painted when the marker's owner ID
	 * this provider's ID
	 * .
	 * @param ownerId the ID
	 */
	public void setOwnerId(UniversalID ownerId);

	/**
	 * Get the component to show the margin markers.
	 * @return the component
	 */
	public JComponent getComponent();

	/**
	 * Return true if can be resized.
	 * @return true if can be resized.
	 */
	public boolean isResizeable();

	/**
	 * Called to notify this margin provider that the current screen information has changed.
	 * 
	 * @param listingPanel the listing panel.
	 * @param addressIndexMap the address index map to use.
	 * @param pixelMap the vertical pixel map to use.
	 */
	public void screenDataChanged(ListingPanel listingPanel, AddressIndexMap addressIndexMap,
			VerticalPixelAddressMap pixelMap);

	/**
	 * Called from the client when their location changes internally.  This is different from a tool
	 * location event, which is considered a global event.
	 * @param location the location
	 */
	public void setLocation(ProgramLocation location);

	/**
	 * Get the marker location for the given x, y point.
	 * 
	 * @param x the horizontal coordinate.
	 * @param y the vertical coordinate.
	 * @return the location
	 */
	public MarkerLocation getMarkerLocation(int x, int y);

	/**
	 * Called when the client is done with this provider.
	 */
	public void dispose();
}
