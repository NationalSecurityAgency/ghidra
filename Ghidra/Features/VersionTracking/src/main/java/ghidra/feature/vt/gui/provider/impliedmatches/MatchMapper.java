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
package ghidra.feature.vt.gui.provider.impliedmatches;

import ghidra.feature.vt.api.main.*;
import ghidra.program.model.address.Address;

/**
 * A custom class that maps this package's table row object type to a match so that we may 
 * reuse existing match columns.
 */
class MatchMapper implements VTMatch {

	private final ImpliedMatchWrapperRowObject rowObject;
	private final AssociationStub assocationStub;

	MatchMapper(ImpliedMatchWrapperRowObject rowObject) {
		this.rowObject = rowObject;
		assocationStub =
			new AssociationStub(rowObject.getSourceAddress(), rowObject.getDestinationAddress(),
				rowObject.getAssociationType());
	}

	@Override
	public VTAssociation getAssociation() {
		VTMatch existingMatch = rowObject.getMatch();
		if (existingMatch != null) {
			return existingMatch.getAssociation();
		}
		return assocationStub;
	}

	@Override
	public VTScore getConfidenceScore() {
		return rowObject.getConfidenceScore();
	}

	@Override
	public int getDestinationLength() {
		return rowObject.getDestinationLength();
	}

	@Override
	public VTMatchSet getMatchSet() {
		return rowObject.getMatchSet();
	}

	@Override
	public VTScore getSimilarityScore() {
		return rowObject.getSimilarityScore();
	}

	@Override
	public Address getSourceAddress() {
		return rowObject.getSourceAddress();
	}

	@Override
	public Address getDestinationAddress() {
		return rowObject.getDestinationAddress();
	}

	@Override
	public int getSourceLength() {
		return rowObject.getSourceLength();
	}

	@Override
	public VTMatchTag getTag() {
		return rowObject.getTag();
	}

	@Override
	public void setTag(VTMatchTag tag) {
		// no-op; cannot set the tag on the row object
	}

}
