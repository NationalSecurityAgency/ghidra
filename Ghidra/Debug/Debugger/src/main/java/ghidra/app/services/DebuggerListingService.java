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

import ghidra.app.plugin.core.debug.gui.action.LocationTrackingSpec;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.listing.MultiBlendedListingBackgroundColorModel;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramSelection;

/**
 * A service providing access to the main listing panel
 */
@ServiceInfo( //
	defaultProvider = DebuggerListingPlugin.class, //
	description = "Replacement CodeViewerService for Debugger" //
)
public interface DebuggerListingService extends CodeViewerService {

	/**
	 * A listener for changes in location tracking specification
	 */
	interface LocationTrackingSpecChangeListener {
		/**
		 * The specification has changed
		 * 
		 * @param spec the new specification
		 */
		void locationTrackingSpecChanged(LocationTrackingSpec spec);
	}

	/**
	 * Set the tracking specification of the listing. Navigates immediately.
	 * 
	 * @param spec the desired specification
	 */
	void setTrackingSpec(LocationTrackingSpec spec);

	/**
	 * Get the tracking specification of the listing.
	 * 
	 * @return the current specification
	 */
	LocationTrackingSpec getTrackingSpec();

	/**
	 * Add a listener for changes to the tracking specification.
	 * 
	 * @param listener the listener to receive change notifications
	 */
	void addTrackingSpecChangeListener(LocationTrackingSpecChangeListener listener);

	/**
	 * Remove a listener for changes to the tracking specification.
	 * 
	 * @param listener the listener receiving change notifications
	 */
	void removeTrackingSpecChangeListener(LocationTrackingSpecChangeListener listener);

	/**
	 * Set the selection of addresses in this listing.
	 * 
	 * @param selection the desired selection
	 */
	void setCurrentSelection(ProgramSelection selection);

	/**
	 * Navigate to the given address
	 * 
	 * @param address the desired address
	 * @param centerOnScreen true to center the cursor in the listing
	 * @return true if the request was effective
	 */
	boolean goTo(Address address, boolean centerOnScreen);

	/**
	 * Obtain a coloring background model suitable for the given listing
	 * 
	 * <p>
	 * This may be used, e.g., to style an alternative view in the same manner as listings managed
	 * by this service. Namely, this provides coloring for memory state and the user's cursor.
	 * Coloring for tracked locations and the marker service in general must still be added
	 * separately, since they incorporate additional dependencies.
	 * 
	 * @param listingPanel the panel to be colored
	 * @return a blended background color model implementing the common debugger listing style
	 */
	MultiBlendedListingBackgroundColorModel createListingBackgroundColorModel(
			ListingPanel listingPanel);
}
