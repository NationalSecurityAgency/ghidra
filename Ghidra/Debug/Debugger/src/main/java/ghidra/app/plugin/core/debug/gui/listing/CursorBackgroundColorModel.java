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
import java.util.Objects;

import ghidra.GhidraOptions;
import ghidra.app.util.viewer.listingpanel.ListingBackgroundColorModel;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.framework.options.AutoOptions;
import ghidra.framework.options.AutoOptions.Wiring;
import ghidra.framework.options.annotation.AutoOptionConsumed;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;

class CursorBackgroundColorModel implements ListingBackgroundColorModel {
	private Color defaultBackgroundColor;
	private ListingPanel listingPanel;
	private AddressIndexMap addressIndexMap;

	@AutoOptionConsumed(category = {}, name = GhidraOptions.HIGHLIGHT_CURSOR_LINE_COLOR)
	private Color cursorColor = GhidraOptions.DEFAULT_CURSOR_LINE_COLOR;
	@AutoOptionConsumed(category = {}, name = GhidraOptions.HIGHLIGHT_CURSOR_LINE)
	private boolean doHighlight = true;
	@SuppressWarnings("unused")
	private final Wiring autoOptionsWiring;

	public CursorBackgroundColorModel(DebuggerListingPlugin plugin, ListingPanel listingPanel) {
		autoOptionsWiring = AutoOptions.wireOptions(plugin, this);
		modelDataChanged(listingPanel);
	}

	@Override
	public Color getBackgroundColor(BigInteger index) {
		if (listingPanel == null || !doHighlight) {
			return defaultBackgroundColor;
		}
		ProgramLocation loc = listingPanel.getProgramLocation();
		if (loc == null) {
			return defaultBackgroundColor;
		}
		Address cursorAddress = loc.getAddress();
		Address address = addressIndexMap.getAddress(index);
		if (!Objects.equals(cursorAddress, address)) {
			return defaultBackgroundColor;
		}
		return cursorColor;
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
	public void modelDataChanged(ListingPanel newListingPanel) {
		this.addressIndexMap = newListingPanel.getAddressIndexMap();
		this.listingPanel = newListingPanel;
	}
}
