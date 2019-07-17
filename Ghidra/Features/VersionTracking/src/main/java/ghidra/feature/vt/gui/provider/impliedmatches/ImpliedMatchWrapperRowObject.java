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
package ghidra.feature.vt.gui.provider.impliedmatches;

import ghidra.feature.vt.api.main.*;

/**
 * A row object for the {@link VTImpliedMatchesTableModel}.  This object will represent a 
 * {@link VTMatch}, either a possible one or an existing one. 
 */
class ImpliedMatchWrapperRowObject extends VTImpliedMatchInfo {

	private VTMatch existingMatch;

	ImpliedMatchWrapperRowObject(VTImpliedMatchInfo impliedMatch, VTMatch existingMatch) {
		super(impliedMatch.getMatchSet(), impliedMatch.getSourceReference(),
			impliedMatch.getDestinationReference());

		this.existingMatch = existingMatch;

		setAssociationType(impliedMatch.getAssociationType());
		setConfidenceScore(impliedMatch.getConfidenceScore());
		setSimilarityScore(impliedMatch.getConfidenceScore());
		setDestinationAddress(impliedMatch.getDestinationAddress());
		setSourceAddress(impliedMatch.getSourceAddress());
		setDestinationLength(impliedMatch.getDestinationLength());
		setSourceLength(impliedMatch.getSourceLength());
		setTag(impliedMatch.getTag());
	}

	void setMatch(VTMatch match) {
		this.existingMatch = match;
	}

	public VTMatch getMatch() {
		return existingMatch;
	}

	public boolean isRealMatch() {
		return existingMatch != null;
	}

	@Override
	public VTAssociationType getAssociationType() {
		if (existingMatch != null) {
			return existingMatch.getAssociation().getType();
		}

		return super.getAssociationType();
	}

	@Override
	public VTScore getConfidenceScore() {
		if (existingMatch != null) {
			return existingMatch.getConfidenceScore();
		}
		return super.getConfidenceScore();
	}

	@Override
	public int getDestinationLength() {
		if (existingMatch != null) {
			return existingMatch.getDestinationLength();
		}
		return super.getDestinationLength();
	}

	@Override
	public VTMatchSet getMatchSet() {
		if (existingMatch != null) {
			return existingMatch.getMatchSet();
		}
		return super.getMatchSet();
	}

	@Override
	public VTScore getSimilarityScore() {
		if (existingMatch != null) {
			return existingMatch.getSimilarityScore();
		}
		return super.getSimilarityScore();
	}

	@Override
	public int getSourceLength() {
		if (existingMatch != null) {
			return existingMatch.getSourceLength();
		}
		return super.getSourceLength();
	}

	@Override
	public VTMatchTag getTag() {
		if (existingMatch != null) {
			return existingMatch.getTag();
		}
		return super.getTag();
	}

	@Override
	public boolean equals(Object obj) {
		if (!super.equals(obj)) {
			return false;
		}

		if (!getClass().equals(obj.getClass())) {
			return false;
		}

		ImpliedMatchWrapperRowObject other = (ImpliedMatchWrapperRowObject) obj;
		if (getSourceReference().equals(other.getSourceReference())) {
			return false;
		}

		if (getDestinationReference().equals(other.getDestinationReference())) {
			return false;
		}

		return isRealMatch() == other.isRealMatch();
	}
}
