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
package ghidra.feature.vt.api;

import ghidra.feature.vt.api.main.*;

/**
 * A possible match between source and destination.
 */
public class FunctionPair {

	private FunctionNode sourceNode;	// Function from the source program
	private FunctionNode destNode;		// Function from the destination program
	private double simResult;			// Similarity of the pair (0.0 to 1.0)
	private double confResult;			// Confidence score of the pair

	/**
	 * Constructor
	 * @param source the source function
	 * @param dest the destination function
	 * @param simRes the computed similarity score
	 * @param confRes the computed confidence score
	 */
	public FunctionPair(FunctionNode source, FunctionNode dest, double simRes, double confRes) {
		this.sourceNode = source;
		this.destNode = dest;
		this.simResult = simRes;
		this.confResult = confRes;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((destNode == null) ? 0 : destNode.hashCode());
		result = prime * result + ((sourceNode == null) ? 0 : sourceNode.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		FunctionPair other = (FunctionPair) obj;
		if (destNode == null) {
			if (other.destNode != null) {
				return false;
			}
		}
		else if (!destNode.equals(other.destNode)) {
			return false;
		}
		if (sourceNode == null) {
			if (other.sourceNode != null) {
				return false;
			}
		}
		else if (!sourceNode.equals(other.sourceNode)) {
			return false;
		}
		return true;
	}

	/**
	 * Compute the formal Version Tracking match record corresponding to this pair
	 * @param matchSet is the match set the record should be added to
	 * @return the match record
	 */
	public VTMatchInfo getMatch(VTMatchSet matchSet) {
		VTMatchInfo result = new VTMatchInfo(matchSet);
		result.setSimilarityScore(new VTScore(simResult));
		result.setConfidenceScore(new VTScore(confResult));
		result.setAssociationType(VTAssociationType.FUNCTION);
		result.setSourceAddress(sourceNode.getAddress());
		result.setDestinationAddress(destNode.getAddress());
		result.setSourceLength(sourceNode.getLen());
		result.setDestinationLength(destNode.getLen());
		return result;
	}

	@Override
	public String toString() {
		return sourceNode.toString() + "," + destNode.toString();
	}

	/**
	 * @return info about the source function
	 */
	public FunctionNode getSourceNode() {
		return sourceNode;
	}

	/**
	 * @return info about the destination function
	 */
	public FunctionNode getDestNode() {
		return destNode;
	}

	/**
	 * @return the similarity score of the pair
	 */
	public double getSimResult() {
		return simResult;
	}

	/**
	 * @return the confidence score of the pair
	 */
	public double getConfResult() {
		return confResult;
	}
}
