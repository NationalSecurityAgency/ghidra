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
package ghidra.feature.vt.api.impl;

import ghidra.feature.vt.api.db.VTMatchSetDB;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.Msg;

import java.io.IOException;

public class ProgramCorrelatorInfoImpl implements VTProgramCorrelatorInfo {

	private String correlatorClassName;
	private String name;
	private AddressSet sourceAddressSet;
	private AddressSet destinationAddressSet;
	private Options options;
	private final VTMatchSetDB matchSetDB;

	public ProgramCorrelatorInfoImpl(VTMatchSetDB matchSet) {
		this.matchSetDB = matchSet;
	}

	@Override
	public String getCorrelatorClassName() {
		if (correlatorClassName == null) {
			correlatorClassName = matchSetDB.getProgramCorrelatorClassName();
		}
		return correlatorClassName;
	}

	@Override
	public String getName() {
		if (name == null) {
			name = matchSetDB.getProgramCorrelatorName();
		}
		return name;
	}

	@Override
	public AddressSetView getSourceAddressSet() {
		if (sourceAddressSet == null) {
			try {
				sourceAddressSet = matchSetDB.getSourceAddressSet();
			}
			catch (IOException e) {
				Msg.showError(
					this,
					null,
					"Unable to Retrieve ProgramCorrelatorInfo",
					"Unexpected exception retrieving source addresses: " + getCorrelatorClassName(),
					e);
			}
		}
		return sourceAddressSet;
	}

	@Override
	public AddressSetView getDestinationAddressSet() {
		if (destinationAddressSet == null) {
			try {
				destinationAddressSet = matchSetDB.getDestinationAddressSet();
			}
			catch (IOException e) {
				Msg.showError(this, null, "Unable to Retrieve ProgramCorrelatorInfo",
					"Unexpected exception retrieving destination addresses: " +
						getCorrelatorClassName(), e);
			}
		}
		return destinationAddressSet;
	}

	@Override
	public Options getOptions() {
		if (options == null) {
			options = matchSetDB.getOptions();
		}
		return options;
	}
}
