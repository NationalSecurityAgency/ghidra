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
package ghidra.bytepatterns.bitcluster;

import generic.stl.Pair;
import ghidra.util.bytesearch.DittedBitSequence;

import java.util.HashMap;
import java.util.HashSet;

public class Face extends DittedBitSequence implements Comparable<Face> {
	private int weight;					//Typically represents the number of data points this face contains.
	private double dit_ratio;			// 1 / (2 to the number of dits)
	private HashSet<Face> children;		//A set of faces this face contains. (Used in the hierarchy of ditted pattern finding.)
	public String strID;				//A unique string ID. Two faces with the same ID ought to be thought of as the same.
	private Pair<Face, Face> joinOf;	//Keep track of what pair of faces made this face (if it was created as a join).

	//Constructor from a sequence of bytes.
	public Face(byte[] bytes) {
		super(bytes);
		this.weight = 1;
		this.children = new HashSet<Face>();
		this.joinOf = null;
		this.strID = this.toString();
		dit_ratio = 1.0 / Math.pow(2.0, getNumUncertainBits());
	}

	//Finds the "join" of two faces: the smallest face that contains both f1 and f2.
	public Face(Face f1, Face f2, HashSet<Face> patterns, int maxDim, boolean addf1) {
		super(f1, f2);
		if (this.getNumUncertainBits() <= maxDim) {							//If the dimension is too high, the rest isn't worth doing.
			this.strID = this.toString();
			this.weight = 0;
			this.children = new HashSet<Face>();
			this.joinOf = new Pair<Face, Face>(f1, f2);			//We'll need to know *how* this edge was made.

			//Set up the children for tracking hierarchy.
			for (Face kid : patterns) {
				DittedBitSequence temp = new DittedBitSequence(this, kid);
				if (temp.getNumUncertainBits() == this.getNumUncertainBits()) {				//Check to see if kid is a subface of this.
					this.children.add(kid);
					this.weight += kid.getWeight();
				}
			}
			if (addf1) {											//Used when f1 isn't already a pattern.
				this.children.add(f1);
				this.weight += f1.getWeight();
			}
		}
		dit_ratio = 1.0 / Math.pow(2.0, getNumUncertainBits());
	}

	//Returns the weight of the face.
	public int getWeight() {
		return this.weight;
	}

	//Alters the weight of the face.
	public void incrementWeight() {
		this.weight++;
	}

	//Returns children, duh.
	public HashSet<Face> getChildren() {
		return this.children;
	}

	//Given that this is the best clustering edge available, check to see if it's joining things that need to be joined.
	public boolean meetsCriteria(HashSet<Face> patterns, HashMap<String, Face> faceByName) {
		if (!patterns.contains(this.joinOf.first)) {
			return false;
		}
		else if (!patterns.contains(this.joinOf.second)) {
			return false;
		}
		else if (faceByName.containsKey(this.strID)) {
			return false;
		}
		return true;
	}

	//A measurement of "how full" the face is with weight as compared to the number of vertices it would be as a cube.
	public double ratioFilled() {
		return this.weight * dit_ratio;
	}

	//Comparator for use in determining which edges to add to hierarchical agglomerative clustering.
	@Override
	public int compareTo(Face o) {
		double val = this.ratioFilled() - o.ratioFilled();
		if (val == 0) {
			return this.strID.compareTo(o.strID);
		}
		return (val > 0 ? 1 : -1);
	}
}
