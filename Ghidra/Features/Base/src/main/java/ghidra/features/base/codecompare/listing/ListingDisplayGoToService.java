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

import docking.DockingWindowManager;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.*;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * This is a GoToService for a listing code compare panel. It allows the goTo to occur relative to
 * the left or right listing panel of a dual listing panel, since the left and right sides can be
 * displaying totally different addresses.
 */
class ListingDisplayGoToService implements GoToService {

	private ListingPanel listingPanel;

	/**
	 * Constructs a goTo service for a dual listing panel.
	 * @param listingPanel the listing panel to be navigated to
	 */
	ListingDisplayGoToService(ListingPanel listingPanel) {
		this.listingPanel = listingPanel;
	}

	@Override
	public GoToOverrideService getOverrideService() {
		return null;
	}

	@Override
	public boolean goTo(ProgramLocation loc) {
		return doGoTo(loc);
	}

	@Override
	public boolean goTo(Navigatable navigatable, Program program, Address address,
			Address refAddress) {
		return doGoTo(new ProgramLocation(program, address));
	}

	@Override
	public boolean goTo(ProgramLocation loc, Program program) {
		return doGoTo(loc);
	}

	@Override
	public boolean goTo(Navigatable navigatable, ProgramLocation loc, Program program) {
		return doGoTo(loc);
	}

	@Override
	public boolean goTo(Navigatable navigatable, Address goToAddress) {
		return doGoTo(goToAddress);
	}

	@Override
	public boolean goTo(Address currentAddress, Address goToAddress) {
		return doGoTo(goToAddress);
	}

	@Override
	public boolean goTo(Address goToAddress) {
		return doGoTo(goToAddress);
	}

	@Override
	public boolean goTo(Address goToAddress, Program program) {
		return doGoTo(goToAddress);
	}

	@Override
	public boolean goToExternalLocation(ExternalLocation extLoc, boolean checkNavigationOption) {
		Msg.showError(this, null, "Go To Failed!",
			"Can't naviagate to an external function from here");
		return false;
	}

	@Override
	public boolean goToExternalLocation(Navigatable navigatable, ExternalLocation extLoc,
			boolean checkNavigationOption) {
		Msg.showError(this, null, "Go To Failed!",
			"Can't naviagate to an external function from here");
		return false;
	}

	@Override
	public boolean goToQuery(Address fromAddr, QueryData queryData, GoToServiceListener listener,
			TaskMonitor monitor) {
		throw new UnsupportedOperationException(
			"Go To Address or Label Query is not allowed in a dual listing view.");
	}

	@Override
	public boolean goToQuery(Navigatable navigatable, Address fromAddr, QueryData queryData,
			GoToServiceListener listener, TaskMonitor monitor) {
		throw new UnsupportedOperationException(
			"Go To Address or Label Query is not allowed in a dual listing view.");
	}

	@Override
	public void setOverrideService(GoToOverrideService override) {
		// ignored
	}

	@Override
	public Navigatable getDefaultNavigatable() {
		return new ListingDisplayNavigator(listingPanel, this);
	}

	private boolean doGoTo(Address addr) {

		// Only go if the address is in the listing's current address set.
		if (!validateAddress(addr)) {
			return false;
		}

		return listingPanel.goTo(addr);
	}

	private boolean doGoTo(ProgramLocation loc) {
		if (loc == null) {
			return false;
		}

		// Only go if the location address is in the listing's current address set.
		if (!validateAddress(loc.getAddress())) {
			return false;
		}

		return listingPanel.goTo(loc);
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
		AddressIndexMap map = listingPanel.getAddressIndexMap();
		AddressSetView addresses = map.getOriginalAddressSet();
		if (!addresses.contains(addr)) {
			DockingWindowManager.getActiveInstance().setStatusText(
				"\"" + addr.toString() + "\" is outside the current listing's view.");
			return false;
		}
		return true;
	}
}
