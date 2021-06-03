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
package ghidra.app.util.viewer.listingpanel;

import java.math.BigInteger;

import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.internal.LayoutLockedFieldPanelCoordinator;
import docking.widgets.fieldpanel.support.ViewerPosition;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.program.model.address.Address;
import ghidra.program.util.ListingAddressCorrelation;
import ghidra.program.util.ProgramLocation;

/**
 * Coordinates cursor location and scrolling between the two sides of a ListingCodeComparisonPanel.
 */
public class ListingComparisonFieldPanelCoordinator extends LayoutLockedFieldPanelCoordinator
		implements DualListingFieldPanelCoordinator {

	private ListingCodeComparisonPanel dualListingPanel;
	private ListingAddressCorrelation addressCorrelation;
	private Address[] lockLineAddresses = new Address[2];

	/**
	 * Constructor for this dual listing field panel coordinator.
	 * @param dualListingPanel the dual listing to be controlled by this coordinator.
	 */
	public ListingComparisonFieldPanelCoordinator(ListingCodeComparisonPanel dualListingPanel) {
		super(new FieldPanel[] { dualListingPanel.getLeftPanel().getFieldPanel(),
			dualListingPanel.getRightPanel().getFieldPanel() });
		this.dualListingPanel = dualListingPanel;
	}

	/**
	 * Sets a new address correlation for associating addresses between the left and right sides.
	 * The field panels can then be coordinated by locking the layouts together whenever the
	 * current location on one side can be correlated with a location on the other side.
	 * @param addressCorrelation the correlation to use for locking the two sides together for
	 * scrolling.
	 */
	public void setCorrelation(ListingAddressCorrelation addressCorrelation) {
		this.addressCorrelation = addressCorrelation;
		resetLockedLines();
	}

	@Override
	public void leftLocationChanged(ProgramLocation leftLocation) {
		if (addressCorrelation == null) {
			return; // Do nothing since no address correlator.
		}
		Address leftAddress = leftLocation.getAddress();
		if (leftAddress == null) {
			return; // Do nothing since can't get a location address.
		}
		// The correlation only gives a right side address for a left side address that is a code unit minimum.
		Address rightAddress = addressCorrelation.getAddressInSecond(leftAddress);
		if (rightAddress == null) {
			return; // Do nothing since can't get a matching address.
		}
		// Got an address so let's try to lock the two panels at the indexes for the matching addresses.
		setLockedAddresses(leftAddress, rightAddress);

		FieldPanel fp = dualListingPanel.getLeftPanel().getFieldPanel();
		adjustFieldPanel(fp);
	}

	@Override
	public void rightLocationChanged(ProgramLocation rightLocation) {
		if (addressCorrelation == null) {
			return; // Do nothing since no address correlator.
		}
		Address rightAddress = rightLocation.getAddress();
		if (rightAddress == null) {
			return; // Do nothing since can't get a location address.
		}
		// The correlation only gives a left side address for a right side address that is a code unit minimum.
		Address leftAddress = addressCorrelation.getAddressInFirst(rightAddress);
		if (leftAddress == null) {
			return; // Do nothing since can't get a matching address.
		}
		// Got an address so let's try to lock the two panels at the indexes for the matching addresses.
		setLockedAddresses(leftAddress, rightAddress);

		FieldPanel fp = dualListingPanel.getRightPanel().getFieldPanel();
		adjustFieldPanel(fp);
	}

	/**
	 * Kicks the field panels viewChanged() method so that the field panels will realign their
	 * layouts using the locked line numbers.
	 * 
	 * @param fp the field panel that has focus.
	 */
	void adjustFieldPanel(FieldPanel fp) {
		ViewerPosition viewerPosition = fp.getViewerPosition();
		BigInteger topIndex = viewerPosition.getIndex();
		int topXOffset = viewerPosition.getXOffset();
		int topYOffset = viewerPosition.getYOffset();
		viewChanged(fp, topIndex, topXOffset, topYOffset);
	}

	/**
	 * Sets the left and right addresses that should currently be locked together for
	 * synchronized scrolling.
	 * 
	 * @param leftAddress the address in the left listing.
	 * @param rightAddress the address in the right listing.
	 */
	void setLockedAddresses(Address leftAddress, Address rightAddress) {
		lockLineAddresses[0] = leftAddress;
		lockLineAddresses[1] = rightAddress;
		ListingPanel leftListingPanel = dualListingPanel.getLeftPanel();
		ListingPanel rightListingPanel = dualListingPanel.getRightPanel();
		AddressIndexMap leftAddressIndexMap = leftListingPanel.getAddressIndexMap();
		AddressIndexMap rightAddressIndexMap = rightListingPanel.getAddressIndexMap();

		BigInteger leftIndex =
			(leftAddress != null) ? leftAddressIndexMap.getIndex(leftAddress) : null;
		BigInteger rightIndex =
			(rightAddress != null) ? rightAddressIndexMap.getIndex(rightAddress) : null;

		BigInteger[] lineNumbers =
			new BigInteger[] { (leftIndex != null) ? leftIndex : BigInteger.ZERO,
				(rightIndex != null) ? rightIndex : BigInteger.ZERO };
		setLockedLines(lineNumbers);
	}

	/**
	 * Gets the left and right addresses that are currently locked together for synchronized 
	 * scrolling.
	 * 
	 * @return an array containing the left (index 0) and right (index 1) addresses that are 
	 * locked together.
	 */
	Address[] getLockedAddresses() {
		return lockLineAddresses;
	}
}
