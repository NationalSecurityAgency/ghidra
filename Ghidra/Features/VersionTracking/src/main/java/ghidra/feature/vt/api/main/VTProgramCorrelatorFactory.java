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
package ghidra.feature.vt.api.main;

import ghidra.feature.vt.api.util.VTOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;

public interface VTProgramCorrelatorFactory extends ExtensionPoint {

	/**
	 * Returns the name of the correlator for display to the user in the GUI.
	 * @return the name of the correlator
	 */
	public String getName();

	/**
	 * Returns the description of the correlator for display to the user in the GUI.
	 * @return the description of the correlator
	 */
	public String getDescription();

	/**
	 * Returns the listing priority of the correlator; lower means higher in the list.
	 * @return the listing priority of the correlator
	 */
	public int getPriority();

	/**
	 * Returns the restriction preference of the correlator.
	 * @return the restriction preference of the correlator
	 */
	public VTProgramCorrelatorAddressRestrictionPreference getAddressRestrictionPreference();

	/**
	 * Returns an options action that contains a list of all supported options for the algorithm and
	 * their default values.  Override if you need to provide other than the
	 * @return an options action that contains a list of all supported options for the algorithm and
	 * their default values.
	 */
	public VTOptions createDefaultOptions();

	/**
	 * Returns a VTProgramCorrelator instance created specifically for the given parameters.
	 * @param serviceProvider a service provider to access tool services.
	 * @param sourceProgram the source program for this correlation.
	 * @param sourceAddressSet the set of addresses in the source program to consider in this correlation.
	 * @param destinationProgram the destination program for this correlation.
	 * @param destinationAddressSet the set of addresses in the destination program to consider in
	 * this correlation.
	 * @param options the options to use for this correlation.
	 * @return a new VTProgramCorrelator instance created specifically for this set of given parameters.
	 */
	public VTProgramCorrelator createCorrelator(ServiceProvider serviceProvider,
			Program sourceProgram, AddressSetView sourceAddressSet, Program destinationProgram,
			AddressSetView destinationAddressSet, VTOptions options);
}
