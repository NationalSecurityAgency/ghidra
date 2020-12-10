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
package ghidra.app.plugin.core.debug.gui.listing;

import java.awt.Color;
import java.math.BigInteger;

import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.util.viewer.listingpanel.ListingBackgroundColorModel;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.framework.options.AutoOptions;
import ghidra.framework.options.annotation.AutoOptionConsumed;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

public abstract class DebuggerTrackedRegisterListingBackgroundColorModel
		implements ListingBackgroundColorModel {
	private Color defaultBackgroundColor;
	private Program program;
	private AddressIndexMap addressIndexMap;

	// TODO: Seems I should at least rename this option
	@AutoOptionConsumed(name = DebuggerResources.OPTION_NAME_COLORS_REGISTER_MARKERS)
	Color trackingColor;
	@SuppressWarnings("unused")
	private final AutoOptions.Wiring autoOptionsWiring;

	public DebuggerTrackedRegisterListingBackgroundColorModel(DebuggerListingPlugin plugin,
			ListingPanel listingPanel) {
		autoOptionsWiring = AutoOptions.wireOptions(plugin, this);
		modelDataChanged(listingPanel);
	}

	@Override
	public Color getBackgroundColor(BigInteger index) {
		if (program == null) {
			return defaultBackgroundColor;
		}
		ProgramLocation loc = getTrackedLocation();
		if (loc == null) {
			return defaultBackgroundColor;
		}
		Address address = addressIndexMap.getAddress(index);
		if (!loc.getAddress().equals(address)) {
			return defaultBackgroundColor;
		}
		return trackingColor;
	}

	@Override
	public Color getDefaultBackgroundColor() {
		return defaultBackgroundColor;
	}

	@Override
	public void setDefaultBackgroundColor(Color c) {
		defaultBackgroundColor = c;
	}

	@Override
	public void modelDataChanged(ListingPanel listingPanel) {
		this.program = listingPanel == null ? null : listingPanel.getProgram();
		this.addressIndexMap = listingPanel == null ? null : listingPanel.getAddressIndexMap();
	}

	protected abstract ProgramLocation getTrackedLocation();
}
