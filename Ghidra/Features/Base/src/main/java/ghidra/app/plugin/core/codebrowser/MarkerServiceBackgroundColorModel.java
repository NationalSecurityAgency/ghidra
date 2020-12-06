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
package ghidra.app.plugin.core.codebrowser;

import java.awt.Color;
import java.math.BigInteger;

import docking.widgets.fieldpanel.support.BackgroundColorModel;
import ghidra.app.services.MarkerService;
import ghidra.app.util.viewer.listingpanel.ListingBackgroundColorModel;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * {@link BackgroundColorModel} for coloring the Listing based on the {@link MarkerService}
 */
public class MarkerServiceBackgroundColorModel implements ListingBackgroundColorModel {
	private MarkerService markerService;
	private Program program;
	private AddressIndexMap indexMap;
	private Color defaultBackgroundColor = Color.WHITE;

	public MarkerServiceBackgroundColorModel(MarkerService markerService, Program program,
			AddressIndexMap indexMap) {
		this.markerService = markerService;
		this.program = program;
		this.indexMap = indexMap;
	}

	public MarkerServiceBackgroundColorModel(MarkerService markerService,
			AddressIndexMap indexMap) {
		this(markerService, null, indexMap);
	}

	@Override
	public Color getBackgroundColor(BigInteger index) {
		Address addr = indexMap.getAddress(index);
		Color color = null;
		if (addr != null) {
			if (program == null) {
				color = markerService.getBackgroundColor(addr);
			}
			else {
				color = markerService.getBackgroundColor(program, addr);
			}
		}
		if (color == null) {
			color = defaultBackgroundColor;
		}
		return color;
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
		this.program = listingPanel.getProgram();
		this.indexMap = listingPanel.getAddressIndexMap();
	}
}
