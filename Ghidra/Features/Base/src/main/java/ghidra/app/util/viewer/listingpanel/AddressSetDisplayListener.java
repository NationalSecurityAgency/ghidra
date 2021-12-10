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

import ghidra.program.model.address.AddressSetView;

/**
 * Interface for being notified whenever the set of visible addresses change in the listing.
 */
public interface AddressSetDisplayListener {
	/**
	 * Callback whenever the set of visible addresses change in the listing.
	 * @param visibleAddresses the current set of visible addresses in the listing.  If no
	 * visible addresses are in the listing view, then an empty AddressSetView will be passed.
	 */
	void visibleAddressesChanged(AddressSetView visibleAddresses);
}
