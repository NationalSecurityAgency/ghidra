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
import java.util.Map.Entry;

import generic.theme.GColor;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.util.viewer.listingpanel.ListingBackgroundColorModel;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.program.TraceProgramView;

public class MemoryStateListingBackgroundColorModel implements ListingBackgroundColorModel {
	private static final Color COLOR_BACKGROUND_ERROR = DebuggerResources.COLOR_BACKGROUND_ERROR;
	private static final GColor COLOR_BACKGROUND_UNKNOWN = DebuggerResources.COLOR_BACKGROUND_STALE;
	private static final Color COLOR_BACKGROUND_UNKNOWN_BLENDED =
		COLOR_BACKGROUND_UNKNOWN.withAlpha(127);

	private Color defaultBackgroundColor = new GColor("color.bg");

	private AddressIndexMap addressIndexMap;
	private TraceProgramView view;
	private TraceMemoryManager memory;

	public MemoryStateListingBackgroundColorModel(ListingPanel listingPanel) {
		modelDataChanged(listingPanel);
	}

	@Override
	public Color getBackgroundColor(BigInteger index) {
		if (view == null) {
			return defaultBackgroundColor;
		}
		Address address = addressIndexMap.getAddress(index);
		if (address == null) {
			return defaultBackgroundColor;
		}

		Entry<Long, TraceMemoryState> state = memory.getViewState(view.getSnap(), address);
		if (state == null) {
			return defaultBackgroundColor;
		}
		switch (state.getValue()) {
			case UNKNOWN:
				return getUnknownColor(address);
			case ERROR:
				return COLOR_BACKGROUND_ERROR;
			default:
				return defaultBackgroundColor;
		}
	}

	protected Color getUnknownColor(Address address) {
		Entry<TraceAddressSnapRange, TraceMemoryState> ent =
			memory.getViewMostRecentStateEntry(view.getSnap(), address);
		if (ent == null || ent.getValue() != TraceMemoryState.KNOWN) {
			return COLOR_BACKGROUND_UNKNOWN;
		}
		TraceMemoryRegion region = memory.getRegionContaining(ent.getKey().getY1(), address);
		if (region != null && !region.isWrite()) {
			return COLOR_BACKGROUND_UNKNOWN_BLENDED;
		}
		return COLOR_BACKGROUND_UNKNOWN;
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
		this.addressIndexMap = listingPanel.getAddressIndexMap();
		Program program = listingPanel.getProgram();
		if (!(program instanceof TraceProgramView view)) {
			this.view = null;
			this.memory = null;
			return;
		}
		this.view = view;
		this.memory = view.getTrace().getMemoryManager();
	}
}
