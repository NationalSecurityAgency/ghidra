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
package ghidra.features.codecompare.functiongraph;

import ghidra.app.util.viewer.listingpanel.ProgramLocationTranslator;
import ghidra.program.util.ListingAddressCorrelation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.datastruct.Duo;
import ghidra.util.datastruct.Duo.Side;

/**
 * A class to synchronize locations between the left and right Function Graph comparison panels.
 */
class FgDisplaySynchronizer {

	private Duo<FgDisplay> displays;
	private ProgramLocationTranslator locationTranslator;

	FgDisplaySynchronizer(Duo<FgDisplay> displays, ListingAddressCorrelation correlation) {
		this.displays = displays;
		this.locationTranslator = new ProgramLocationTranslator(correlation);
	}

	void setLocation(Side side, ProgramLocation location) {
		// Only set other side's cursor if we are coordinating right now.
		Side otherSide = side.otherSide();
		ProgramLocation otherLocation = locationTranslator.getProgramLocation(otherSide, location);
		if (otherLocation != null) {
			displays.get(otherSide).setLocation(otherLocation);
		}
	}

	void sync(Side side) {
		ProgramLocation programLocation = displays.get(side).getLocation();
		if (programLocation != null) {
			setLocation(side, programLocation);
		}
	}

	void dispose() {
		// this object should probably have a dispose() method
		// locationTranslator.dispose();
	}
}
