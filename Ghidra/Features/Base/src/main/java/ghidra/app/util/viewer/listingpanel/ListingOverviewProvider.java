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

import ghidra.app.nav.Navigatable;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.program.model.listing.Program;

/**
 * An overview component that will be placed to the right side of the listing.
 */
public interface ListingOverviewProvider {
	/**
	 * Returns the component to display in the right margin of the listing.
	 * @return the component
	 */
	public JComponent getComponent();

	/**
	 * Called to notify this margin provider that the current screen information has changed.
	 * 
	 * @param program the program to use
	 * @param map the address index map to use
	 */
	public void screenDataChanged(Program program, AddressIndexMap map);

	/**
	 * Set the component provider that this overview navigates
	 * 
	 * @param navigatable the navigatable provider
	 */
	public void setNavigatable(Navigatable navigatable);

	/**
	 * Clients call this when they are done with this provider.
	 */
	public void dispose();
}
