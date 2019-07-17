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
package ghidra.feature.vt.api.util;

import ghidra.feature.vt.api.main.*;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

public abstract class VTAbstractProgramCorrelatorFactory implements VTProgramCorrelatorFactory {
	private final VTProgramCorrelatorAddressRestrictionPreference addressRestrictionPreference;

	protected VTAbstractProgramCorrelatorFactory(
			VTProgramCorrelatorAddressRestrictionPreference addressRestrictionPreference) {
		this.addressRestrictionPreference = addressRestrictionPreference;
	}

	protected VTAbstractProgramCorrelatorFactory() {
		this(VTProgramCorrelatorAddressRestrictionPreference.PREFER_RESTRICTING_ACCEPTED_MATCHES);
	}

	/**
	 * Returns the name of the correlator for display to the user in the GUI.
	 * @return the name of the correlator
	 */
	@Override
	public abstract String getName();

	/**
	 * Returns the description of the correlator for display to the user in the GUI.
	 * @return the description of the correlator
	 */
	@Override
	public abstract String getDescription();

	@Override
	public String toString() {
		return getName() + ": " + getDescription();
	}

	@Override
	public VTProgramCorrelatorAddressRestrictionPreference getAddressRestrictionPreference() {
		return addressRestrictionPreference;
	}

	/**
	 * Returns an options action that contains a list of all supported options for the algorithm and
	 * their default values.  Override if you need to provide other than the
	 * @return an options action that contains a list of all supported options for the algorithm and
	 * their default values.
	 */
	@Override
	public VTOptions createDefaultOptions() {
		return new VTOptions(getName());
	}

	@Override
	public final VTProgramCorrelator createCorrelator(ServiceProvider serviceProvider,
			Program sourceProgram, AddressSetView sourceAddressSet, Program destinationProgram,
			AddressSetView destinationAddressSet, VTOptions options) {

		return doCreateCorrelator(serviceProvider, sourceProgram, sourceAddressSet,
			destinationProgram, destinationAddressSet, options == null ? createDefaultOptions()
					: (VTOptions) options.copy());
	}

	/** 
	 * This method is added to the interface to enforce the fact that we want options passed into
	 * this method to be copies so that changes during correlation do not spoil the options
	 * of others.
	 */
	protected abstract VTProgramCorrelator doCreateCorrelator(ServiceProvider serviceProvider,
			Program sourceProgram, AddressSetView sourceAddressSet, Program destinationProgram,
			AddressSetView destinationAddressSet, VTOptions options);
}
