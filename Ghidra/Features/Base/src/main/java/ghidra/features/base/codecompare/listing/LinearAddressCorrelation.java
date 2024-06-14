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

import ghidra.features.base.codecompare.panel.ComparisonData;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.util.ListingAddressCorrelation;
import ghidra.util.datastruct.Duo;
import ghidra.util.datastruct.Duo.Side;

/**
 * Creates an address correlation with a simplistic correlation where each address correlates based
 * on an offset from the address set's minimum address.
 */
public class LinearAddressCorrelation implements ListingAddressCorrelation {
	private Duo<ComparisonData> comparisonData;

	public LinearAddressCorrelation(Duo<ComparisonData> comparisonData) {
		this.comparisonData = comparisonData;
	}

	@Override
	public Program getProgram(Side side) {
		return comparisonData.get(LEFT).getProgram();
	}

	@Override
	public AddressSetView getAddresses(Side side) {
		return comparisonData.get(LEFT).getAddressSet();
	}

	@Override
	public Function getFunction(Side side) {
		return null;
	}

	@Override
	public Address getAddress(Side side, Address otherAddress) {
		Side otherSide = side.otherSide();
		if (!isValidAddress(otherSide, otherAddress) || !isCodeUnitStart(otherSide, otherAddress)) {
			return null;
		}
		AddressSetView otherSet = comparisonData.get(otherSide).getAddressSet();
		Address minOtherAddress = otherSet.getMinAddress();
		long offset = otherAddress.subtract(minOtherAddress);
		Address minAddress = comparisonData.get(side).getAddressSet().getMinAddress();
		Address address = minAddress.addWrap(offset);
		if (!isValidAddress(side, address)) {
			return null;
		}
		return normalizeToCodeUnitStart(side, address);
	}

	private boolean isValidAddress(Side side, Address address) {
		AddressSetView addresses = comparisonData.get(side).getAddressSet();
		return addresses.contains(address);
	}

	private boolean isCodeUnitStart(Side side, Address address) {
		Listing listing = getListing(side);
		CodeUnit cu = listing.getCodeUnitAt(address);
		return cu != null;
	}

	private Address normalizeToCodeUnitStart(Side side, Address address) {
		Listing listing = getListing(side);
		CodeUnit cu = listing.getCodeUnitContaining(address);
		Address minAddress = cu.getMinAddress();
		if (isValidAddress(side, minAddress)) {
			return minAddress;
		}
		return null;
	}

	private Listing getListing(Side side) {
		return comparisonData.get(side).getProgram().getListing();
	}

}
