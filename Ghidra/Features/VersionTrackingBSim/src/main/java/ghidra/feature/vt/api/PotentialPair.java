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

/**
 * Given a matching FunctionPair, this object represents a different
 * potential match taken from neighborhoods of the match endpoints.
 */
public class PotentialPair implements Comparable<PotentialPair> {
	private FunctionPair originBridge;		// Accepted match that induced this potential match
	private FunctionNode fromNode;			// Source node of potential match
	private FunctionNode toNode;			// Destination node of potential match
	private double score;					// implication score associated with potential match

	public static final PotentialPair EMPTY_PAIR = new PotentialPair(null, null, 0.0);

	public PotentialPair(FunctionNode src, FunctionNode dest, double sc) {
		fromNode = src;
		toNode = dest;
		score = sc;
	}

	public double getScore() {
		return score;
	}

	public FunctionNode getSource() {
		return fromNode;
	}

	public FunctionNode getDestination() {
		return toNode;
	}

	public FunctionPair getOrigin() {
		return originBridge;
	}

	public void setOrigin(FunctionPair pair) {
		originBridge = pair;
	}

	public void swap() {
		FunctionNode tmp = fromNode;
		fromNode = toNode;
		toNode = tmp;
	}

	@Override
	public int compareTo(PotentialPair o) {
		return Double.compare(score, o.score);
	}
}
