/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.feature.vt.api.util;

import ghidra.feature.vt.api.main.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class VTMatchUtil {

	/**
	 * Get the set of addresses associated with either the source or destination of a version tracking match.
	 * @param vtMatch the version tracking match
	 * @param forSource true means get the addresses for the source part of the match; 
	 * false means get the destination part.
	 * @return the source or destination addresses for the match.
	 */
	public static AddressSetView getMatchAddresses(VTMatch vtMatch, boolean forSource) {
		VTMatchSet matchSet = vtMatch.getMatchSet();
		VTSession session = matchSet.getSession();
		Program program =
			forSource ? session.getSourceProgram()
					: session.getDestinationProgram();
		AddressFactory factory = program.getAddressFactory();
		Address address;
		if (forSource) {
			address = vtMatch.getAssociation().getSourceAddress();
		}
		else {
			address = vtMatch.getAssociation().getDestinationAddress();
		}
		VTAssociation association = vtMatch.getAssociation();
		VTAssociationType associationType = association.getType();
		AddressSetView matchAddresses = null;
		if (associationType == VTAssociationType.FUNCTION) {
			Function function = program.getFunctionManager().getFunctionAt(address);
			if (function != null) {
				matchAddresses = function.getBody();
			}
		}
		else if (associationType == VTAssociationType.DATA) {
			Listing listing = program.getListing();
			Data data = listing.getDataAt(address);
			if (data != null) {
				matchAddresses =
					new AddressSet(data.getMinAddress(), data.getMaxAddress());
			}
		}
		if (matchAddresses == null) {
			matchAddresses = new AddressSet(address, address);
		}
		return matchAddresses;
	}
}
