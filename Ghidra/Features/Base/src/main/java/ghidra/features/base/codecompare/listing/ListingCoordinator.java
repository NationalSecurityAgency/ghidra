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
package ghidra.features.base.codecompare.listing;

import static ghidra.util.datastruct.Duo.Side.*;

import java.math.BigInteger;

import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.internal.LayoutLockedFieldPanelCoordinator;
import docking.widgets.fieldpanel.internal.LineLockedFieldPanelCoordinator;
import docking.widgets.fieldpanel.support.ViewerPosition;
import ghidra.app.util.viewer.listingpanel.ProgramLocationTranslator;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.program.model.address.Address;
import ghidra.program.util.ListingAddressCorrelation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.datastruct.Duo;
import ghidra.util.datastruct.Duo.Side;

/**
 * Keeps two listing panels synchronized, both the view and cursor location
 */
public class ListingCoordinator {
	private Duo<ListingDisplay> displays;
	private Duo<Address> lockLineAddresses = new Duo<>();

	private ProgramLocationTranslator locationTranslator;
	private LineLockedFieldPanelCoordinator viewCoordinator;

	ListingCoordinator(Duo<ListingDisplay> displays, ListingAddressCorrelation correlator) {
		this.displays = displays;
		this.locationTranslator = new ProgramLocationTranslator(correlator);
		FieldPanel left = displays.get(LEFT).getListingPanel().getFieldPanel();
		FieldPanel right = displays.get(RIGHT).getListingPanel().getFieldPanel();
		viewCoordinator = new LayoutLockedFieldPanelCoordinator(left, right);
	}

	/**
	 * notification that the given side change to the given location
	 * @param side the side that changed
	 * @param location the location from the given side
	 */
	void setLocation(Side side, ProgramLocation location) {

		// Only set other side's cursor if we are coordinating right now.
		Side otherSide = side.otherSide();
		ProgramLocation otherLocation = locationTranslator.getProgramLocation(otherSide, location);

		if (otherLocation != null) {
			updateViewCoordinator(side, location, otherLocation);
			displays.get(otherSide).goTo(otherLocation);
			displays.get(side.otherSide()).updateCursorMarkers(otherLocation);
		}

	}

	void dispose() {
		viewCoordinator.dispose();
	}

	/**
	 * synchronized the two listings using the given side as the source
	 * @param side to synchronize from
	 */
	void sync(Side side) {
		adjustFieldPanel(displays.get(side).getListingPanel().getFieldPanel());
		ProgramLocation programLocation = displays.get(side).getProgramLocation();
		if (programLocation != null) {
			setLocation(side, programLocation);
		}
	}

	/**
	 * Kicks the field panels viewChanged() method so that the field panels will realign their
	 * layouts using the locked line numbers.
	 * 
	 * @param fieldPanel the field panel that has focus.
	 */
	private void adjustFieldPanel(FieldPanel fieldPanel) {
		ViewerPosition viewerPosition = fieldPanel.getViewerPosition();
		BigInteger topIndex = viewerPosition.getIndex();
		int topXOffset = viewerPosition.getXOffset();
		int topYOffset = viewerPosition.getYOffset();
		viewCoordinator.viewChanged(fieldPanel, topIndex, topXOffset, topYOffset);
	}

	/**
	 * Sets the left and right addresses that should currently be locked together for
	 * synchronized scrolling.
	 * 
	 * @param leftAddress the address in the left listing.
	 * @param rightAddress the address in the right listing.
	 */
	private void setLockedAddresses(Address leftAddress, Address rightAddress) {
		if (leftAddress == null || rightAddress == null) {
			return;
		}
		lockLineAddresses = new Duo<>(leftAddress, rightAddress);
		AddressIndexMap leftMap = displays.get(LEFT).getListingPanel().getAddressIndexMap();
		AddressIndexMap rightMap = displays.get(RIGHT).getListingPanel().getAddressIndexMap();

		BigInteger leftIndex = leftMap.getIndex(leftAddress);
		BigInteger rightIndex = rightMap.getIndex(rightAddress);
		viewCoordinator.lockLines(leftIndex, rightIndex);
	}

	private void updateViewCoordinator(Side side, ProgramLocation location,
			ProgramLocation otherLocation) {
		Address leftAddress = side == LEFT ? location.getAddress() : otherLocation.getAddress();
		Address rightAddress = side == LEFT ? otherLocation.getAddress() : location.getAddress();
		setLockedAddresses(leftAddress, rightAddress);
		FieldPanel fp = displays.get(side).getListingPanel().getFieldPanel();
		adjustFieldPanel(fp);
	}
}
