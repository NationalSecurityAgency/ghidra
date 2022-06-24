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
 * Interface implemented by classes that provide overview components to the right side of the
 * listing.
 */
public interface OverviewProvider {
	/**
	 * Returns the component to diplay in the right margin of the listing.
	 */
	JComponent getComponent();

	/**
	 * Sets the current program and associated address-index map
	 * 
	 * @param program the program to use.
	 * @param map the address-index map to use.
	 */
	void setProgram(Program program, AddressIndexMap map);

	/**
	 * Set the component provider that this overview navigates
	 * 
	 * @param navigatable the navigatable provider
	 */
	void setNavigatable(Navigatable navigatable);
}
