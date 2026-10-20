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
package ghidra.debug.api.listing;

import ghidra.app.nav.Navigatable;
import ghidra.debug.api.action.LocationTrackingSpec;

public interface DebuggerListing extends Navigatable {
	/**
	 * Get the window title of this debugger listing
	 *
	 * @return Title of window
	 */
	String getTitle();

	/**
	 * Returns boolean if this listing is the main debugger listing
	 *
	 * @return true/false if this is the main listing
	 */
	boolean isMainListing();

	/**
	 * Set a custom title.
	 * <p>
	 * Setting the title here prevents future calls to
	 * {@link docking.ComponentProvider#setTitle(String)} from having any effect. This is done to
	 * preserve the custom
	 * title.
	 *
	 * @param title the title
	 */
	void setCustomTitle(String title);

	/**
	 * Set if this debugger listing should follow the current thread when displaying
	 *
	 * @param follows true/false if this listing should follow the current thread
	 */
	void setFollowsCurrentThread(boolean follows);

	/**
	 * Set what this debugger listing should track as the user performs actions
	 *
	 * @param spec {@link LocationTrackingSpec} describing how/what the listing will track
	 */
	void setTrackingSpec(LocationTrackingSpec spec);
}
