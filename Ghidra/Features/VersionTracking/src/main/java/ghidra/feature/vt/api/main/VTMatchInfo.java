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
package ghidra.feature.vt.api.main;

import ghidra.program.model.address.Address;
import ghidra.util.SystemUtilities;

public class VTMatchInfo {

	private VTAssociationType associationType;
	private VTMatchTag tag;
	private VTScore similarityScore;
	private Address sourceAddress;
	private Address destinationAddress;
	private int sourceLength;
	private int destinationLength;
	protected final VTMatchSet matchSet;
	private VTScore confidenceScore;

	public VTMatchInfo(VTMatchSet vtMatchSet) {
		this.matchSet = vtMatchSet;
	}

	public VTMatchSet getMatchSet() {
		return matchSet;
	}

	public VTAssociationType getAssociationType() {
		return associationType;
	}

	public void setAssociationType(VTAssociationType associationType) {
		this.associationType = associationType;
	}

	public VTMatchTag getTag() {
		return tag;
	}

	public void setTag(VTMatchTag tag) {
		this.tag = tag;
	}

	public VTScore getSimilarityScore() {
		return similarityScore;
	}

	public void setSimilarityScore(VTScore score) {
		this.similarityScore = score;
	}

	public void setConfidenceScore(VTScore score) {
		this.confidenceScore = score;
	}

	public VTScore getConfidenceScore() {
		return confidenceScore;
	}

	public void setSourceAddress(Address sourceAddress) {
		this.sourceAddress = sourceAddress;
	}

	public void setDestinationAddress(Address destinationAddress) {
		this.destinationAddress = destinationAddress;
	}

	public Address getSourceAddress() {
		return sourceAddress;
	}

	public Address getDestinationAddress() {
		return destinationAddress;
	}

	public int getSourceLength() {
		return sourceLength;
	}

	public void setSourceLength(int sourceLength) {
		this.sourceLength = sourceLength;
	}

	public int getDestinationLength() {
		return destinationLength;
	}

	public void setDestinationLength(int destinationLength) {
		this.destinationLength = destinationLength;
	}

	@Override
	public int hashCode() {
		if (sourceAddress != null) {
			return (int) sourceAddress.getOffset();
		}
		return 0;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof VTMatchInfo)) {
			return false;
		}

		VTMatchInfo other = (VTMatchInfo) obj;
		if (destinationLength != other.getDestinationLength()) {
			return false;
		}

		if (getAssociationType() != other.getAssociationType()) {
			return false;
		}

		if (!SystemUtilities.isEqual(similarityScore, other.getSimilarityScore())) {
			return false;
		}
		if (!SystemUtilities.isEqual(confidenceScore, other.getConfidenceScore())) {
			return false;
		}

		if (sourceLength != other.getSourceLength()) {
			return false;
		}

		if (tag != other.getTag()) {
			return false;
		}

		return true;
	}

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		double simScoreValue = getSimilarityScore() == null ? 0.0 : getSimilarityScore().getScore();
		double confScoreValue =
			getConfidenceScore() == null ? 0.0 : getConfidenceScore().getScore();
		buffer.append("\nMatchInfo: ");
		buffer.append("\n  Type               = " + getAssociationType());
		buffer.append("\n  Similarity Score   = " + simScoreValue);
		buffer.append("\n  Confidence Score   = " + confScoreValue);
		buffer.append("\n  SourceAddress      = " + getSourceAddress());
		buffer.append("\n  DestinationAddress = " + getDestinationAddress());
		buffer.append("\n  SourceLength       = " + getSourceLength());
		buffer.append("\n  DestinationLength  = " + getDestinationLength());
		buffer.append("\n  Tagged             = " + getTag());
		return buffer.toString();
	}
}
