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

import ghidra.app.nav.Navigatable;
import ghidra.app.services.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

/**
 * This is a GoToService for a dual listing panel. It allows the goTo to occur relative to the 
 * left or right listing panel of a dual listing panel, since the left and right sides can be
 * displaying totally different addresses.
 */
class DualListingGoToService implements GoToService {

	private ListingCodeComparisonPanel dualListing;
	private boolean isLeftSide;
	private GoToOverrideService overrideService;
	private GoToService goToService;

	/**
	 * Constructs a goTo service for a dual listing panel.
	 * @param goToService the GoToService that this overrides and that can be used when the
	 * GoToService methods don't pertain specifically to the left or right listing panel.
	 * @param dualListing the dual listing panel
	 * @param isLeftSide true means this GoToService is for the left listing panel of the dual listing.
	 */
	DualListingGoToService(GoToService goToService, ListingCodeComparisonPanel dualListing,
			boolean isLeftSide) {
		this.goToService = goToService;
		this.dualListing = dualListing;
		this.isLeftSide = isLeftSide;
	}

	@Override
	public GoToOverrideService getOverrideService() {
		return overrideService;
	}

	@Override
	public boolean goTo(ProgramLocation loc) {
		return dualGoTo(loc);
	}

	@Override
	public boolean goTo(Navigatable navigatable, Program program, Address address,
			Address refAddress) {
		return dualGoTo(new ProgramLocation(program, address));
	}

	@Override
	public boolean goTo(ProgramLocation loc, Program program) {
		return dualGoTo(loc);
	}

	@Override
	public boolean goTo(Navigatable navigatable, ProgramLocation loc, Program program) {
		return dualGoTo(loc);
	}

	@Override
	public boolean goTo(Navigatable navigatable, Address goToAddress) {
		return dualGoTo(goToAddress);
	}

	/**
	 * Checks the address to make sure the listing won't navigate outside the addresses
	 * it currently has loaded. If it is not a valid address it will set a status message 
	 * on the dual listing.
	 * @param addr the address to check
	 * @return true if the address is valid for navigation.
	 */
	private boolean validateAddress(Address addr) {
		if (addr == null) {
			return false;
		}
		AddressSetView addresses =
			isLeftSide ? dualListing.getLeftAddresses() : dualListing.getRightAddresses();
		if (!addresses.contains(addr)) {
			dualListing.setStatusInfo(
				"\"" + addr.toString() + "\" is outside the current listing's view.");
			return false;
		}
		return true;
	}

	private boolean dualGoTo(ProgramLocation loc) {
		if (loc == null) {
			return false;
		}

		// Only go if the location address is in the listing's current address set.
		if (!validateAddress(loc.getAddress())) {
			return false;
		}

		ListingPanel listingPanel =
			(isLeftSide) ? dualListing.getLeftPanel() : dualListing.getRightPanel();
		return listingPanel.goTo(loc);
	}

	private boolean dualGoTo(Address addr) {

		// Only go if the address is in the listing's current address set.
		if (!validateAddress(addr)) {
			return false;
		}

		ListingPanel listingPanel =
			(isLeftSide) ? dualListing.getLeftPanel() : dualListing.getRightPanel();
		return listingPanel.goTo(addr);
	}

	@Override
	public boolean goTo(Address currentAddress, Address goToAddress) {
		return dualGoTo(goToAddress);
	}

	@Override
	public boolean goTo(Address goToAddress) {
		return dualGoTo(goToAddress);
	}

	@Override
	public boolean goTo(Address goToAddress, Program program) {
		return dualGoTo(goToAddress);
	}

	@Override
	public boolean goToExternalLocation(ExternalLocation extLoc, boolean checkNavigationOption) {
		throw new UnsupportedOperationException(
			"Connot Go To an external address from a dual listing view.");
	}

	@Override
	public boolean goToExternalLocation(Navigatable navigatable, ExternalLocation extLoc,
			boolean checkNavigationOption) {
		throw new UnsupportedOperationException(
			"Connot Go To an external address from a dual listing view.");
	}

	@Override
	public boolean goToQuery(Address fromAddr, QueryData queryData, GoToServiceListener listener,
			TaskMonitor monitor) {
		throw new UnsupportedOperationException(
			"Go To Address or Label is not allowed in a dual listing view.");
	}

	@Override
	public boolean goToQuery(Navigatable navigatable, Address fromAddr, QueryData queryData,
			GoToServiceListener listener, TaskMonitor monitor) {
		throw new UnsupportedOperationException(
			"Go To Address or Label is not allowed in a dual listing view.");
	}

	@Override
	public void setOverrideService(GoToOverrideService override) {
		overrideService = override;
	}

	@Override
	public Navigatable getDefaultNavigatable() {
		return goToService.getDefaultNavigatable();
	}
}
