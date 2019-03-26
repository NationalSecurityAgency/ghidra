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
package ghidra.app.util.viewer.listingpanel;

import ghidra.app.util.viewer.util.AddressIndexMap;

import javax.swing.JComponent;

/**
 * Interface implemented by classes that provide overview components to the right side 
 * of the listing.
 */
public interface OverviewProvider {
	/**
	 * Returns the component to diplay in the right margin of the listing.
	 */
	JComponent getComponent();
	
	/**
	 * Sets the AddressIndexMap whenever it changes so that the overview provider has
	 * an current map. 
	 * @param map the current AddressIndexMap of the ListingPanel
	 */
	void setAddressIndexMap(AddressIndexMap map);

}
