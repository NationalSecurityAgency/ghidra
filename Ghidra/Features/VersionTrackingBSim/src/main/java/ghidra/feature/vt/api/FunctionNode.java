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

import java.util.*;
import java.util.Map.Entry;

import generic.lsh.vector.LSHVector;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

/**
 * Information about a single function the correlator is attempting to match
 */
public class FunctionNode implements Comparable<FunctionNode> {

	private final Address addr;							// Address of the function represented, also unique identifier
	private final String name;							// Name of the function this node represents.
	private final LSHVector vec;						// Feature vector
	private ArrayList<Address> callAddresses;			// Addresses of functions this node calls.
	private final Set<FunctionNode> children;			// Who do I call in the call graph?
	private final Set<FunctionNode> parents;			// Who calls me in the call graph?
	private Map<FunctionNode, FunctionPair> associates;	// Potential matches on the other side? And what's our conf?
	private final int len;								// Number of addresses in the body of this function
	private boolean acceptedMatch;						// Has this node been formally matched with something

	/**
	 * Allocate a container for FunctionNodes as needed by the NeighborGenerators.  These are generally small sets
	 * where we need to check containment constantly.
	 * @return the container
	 */
	public static Set<FunctionNode> neigborhoodAllocate() {
		return new HashSet<FunctionNode>();
	}

	public FunctionNode(Function function, LSHVector vector, ArrayList<Address> callAddresses) {
		this.addr = function.getEntryPoint();
		this.name = function.getName();
		this.vec = vector;
		this.callAddresses = callAddresses;	//It will take a second pass through the data to figure out how the call graph fits together.
		this.associates = new HashMap<FunctionNode, FunctionPair>();
		this.children = neigborhoodAllocate();
		this.parents = neigborhoodAllocate();
		int val = (int) function.getBody().getNumAddresses();
		this.len = (val == 0) ? 1 : val;		// Guarantee a non-zero length
		this.acceptedMatch = false;
	}

	@Override
	public int hashCode() {
		return ((addr == null) ? 0 : addr.hashCode());
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
		FunctionNode other = (FunctionNode) obj;
		if (addr == null) {
			if (other.addr != null) {
				return false;
			}
		}
		else if (!addr.equals(other.addr)) {
			return false;
		}
		return true;
	}

	@Override
	public int compareTo(FunctionNode other) {
		return addr.compareTo(other.addr);	// Compare by address
	}

	@Override
	public String toString() {
		return name;
	}

	/**
	 * @return the Address of the entry point of the Function represented by this node
	 */
	public Address getAddress() {
		return addr;
	}

	/**
	 * @return the feature vector associated with this node (function)
	 */
	public LSHVector getVector() {
		return vec;
	}

	/**
	 * Grab the raw call addresses, releasing the memory in the process
	 * @return the list of addresses
	 */
	public List<Address> releaseCallAddresses() {
		List<Address> res = callAddresses;
		callAddresses = null;		// Release our reference to addresses
		return res;
	}

	/**
	 * @return the set of functions (FunctionNodes) called by this function
	 */
	public Set<FunctionNode> getChildren() {
		return children;
	}

	/**
	 * @return the set of functions (FunctionNodes) that call this function
	 */
	public Set<FunctionNode> getParents() {
		return parents;
	}

	/**
	 * Add a (potential) match for this node.  The match
	 * is stored with a FunctionPair object holding similarity information
	 * @param other is the potentially matching FunctionNode
	 * @param pair is the FunctionPair describing the similarity
	 */
	public void addAssociate(FunctionNode other, FunctionPair pair) {
		associates.put(other, pair);
	}

	/**
	 * Remove what was previously considered a potential match.
	 * @param other is the matching FunctionNode
	 */
	public void removeAssociate(FunctionNode other) {
		associates.remove(other);
	}

	/**
	 * Clear all potential matches.
	 */
	public void clearAssociates() {
		associates.clear();
	}

	/**
	 * @return an iterator over all potential matches for this node
	 */
	public Iterator<Entry<FunctionNode, FunctionPair>> getAssociateIterator() {
		return associates.entrySet().iterator();
	}

	/**
	 * If -other- is a potential match, return the FunctionPair describing the similarity
	 * @param other is the possible potential match
	 * @return the FunctionPair describing the match or null, if -other- is not a potential match
	 */
	public FunctionPair findEdge(FunctionNode other) {
		return associates.get(other);
	}

	/**
	 * @return the number of addresses in the function body represented by this node
	 */
	public int getLen() {
		return len;
	}

	/**
	 * @return true if this node has been formally matched by the correlator
	 */
	public boolean isAcceptedMatch() {
		return acceptedMatch;
	}

	/**
	 * Mark that this node has been matched (not matched) by the correlator
	 * @param used is true if this node has been matched
	 */
	public void setAcceptedMatch(boolean used) {
		this.acceptedMatch = used;
	}
}
