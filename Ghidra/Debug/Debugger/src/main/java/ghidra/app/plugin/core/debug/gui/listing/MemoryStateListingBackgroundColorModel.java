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

import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.util.viewer.listingpanel.ListingBackgroundColorModel;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.framework.options.AutoOptions;
import ghidra.framework.options.annotation.AutoOptionConsumed;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.ColorUtils;

public class MemoryStateListingBackgroundColorModel implements ListingBackgroundColorModel {
	private Color defaultBackgroundColor = Color.WHITE;

	private AddressIndexMap addressIndexMap;
	private TraceProgramView view;
	private TraceMemoryManager memory;

	@AutoOptionConsumed(name = DebuggerResources.OPTION_NAME_COLORS_ERROR_MEMORY)
	private Color errorColor;
	@AutoOptionConsumed(name = DebuggerResources.OPTION_NAME_COLORS_STALE_MEMORY)
	private Color unknownColor;
	private Color unknownBlendedColor;
	@SuppressWarnings("unused")
	private final AutoOptions.Wiring autoOptionsWiring;

	public MemoryStateListingBackgroundColorModel(DebuggerListingPlugin plugin,
			ListingPanel listingPanel) {
		autoOptionsWiring = AutoOptions.wireOptions(plugin, this);
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
				return errorColor;
			default:
				return defaultBackgroundColor;
		}
	}

	@AutoOptionConsumed(name = DebuggerResources.OPTION_NAME_COLORS_STALE_MEMORY)
	protected void setUnknownColor(Color unknownColor) {
		computeUnknownBlendedColor(unknownColor, defaultBackgroundColor);
	}

	protected Color getUnknownColor(Address address) {
		Entry<TraceAddressSnapRange, TraceMemoryState> ent =
			memory.getViewMostRecentStateEntry(view.getSnap(), address);
		if (ent == null || ent.getValue() != TraceMemoryState.KNOWN) {
			return unknownColor;
		}
		TraceMemoryRegion region = memory.getRegionContaining(ent.getKey().getY1(), address);
		if (region != null && !region.isWrite()) {
			return unknownBlendedColor;
		}
		return unknownColor;
	}

	@Override
	public Color getDefaultBackgroundColor() {
		return defaultBackgroundColor;
	}

	protected synchronized void computeUnknownBlendedColor(Color unkCol, Color defBg) {
		if (unkCol == null) {
			unknownBlendedColor = defBg;
		}
		else if (defBg == null) {
			unknownBlendedColor = unkCol;
		}
		else {
			unknownBlendedColor = ColorUtils.blend(unkCol, defBg, 0.1f);
		}
	}

	@Override
	public void setDefaultBackgroundColor(Color c) {
		defaultBackgroundColor = c;
		computeUnknownBlendedColor(unknownColor, c);
	}

	@Override
	public void modelDataChanged(ListingPanel listingPanel) {
		this.addressIndexMap = listingPanel.getAddressIndexMap();
		Program program = listingPanel.getProgram();
		if (!(program instanceof TraceProgramView)) {
			this.view = null;
			this.memory = null;
			return;
		}
		this.view = (TraceProgramView) program;
		this.memory = view.getTrace().getMemoryManager();
	}
}
