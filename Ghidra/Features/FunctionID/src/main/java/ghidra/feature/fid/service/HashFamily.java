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
package ghidra.feature.fid.service;

import java.util.Collection;
import java.util.LinkedHashMap;

import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.program.model.address.Address;

/**
 * Container class for the neighborhood of hashes around a function.  Contains
 * the FidHashQuad for the function, for all its parents (callers), all its children (callees),
 * and all the names of the children whose hashes could not be resolved.
 */
public class HashFamily {
	private final Address address;
	private final FidHashQuad hash;
	private LinkedHashMap<Long, FidHashQuad> parents;
	private LinkedHashMap<Long, FidHashQuad> children;

	HashFamily(Address address, FidHashQuad hash) {
		this.address = address;
		this.hash = hash;
		this.parents = new LinkedHashMap<Long, FidHashQuad>();
		this.children = new LinkedHashMap<Long, FidHashQuad>();
	}

	void addParent(FidHashQuad parent) {
		Long key = parent.getFullHash();		// Parents should be unique only up to the full hash
		this.parents.put(key, parent);
	}

	void addChild(FidHashQuad child) {
		Long key = child.getFullHash();			// Children should be unique only up to the full hash
		this.children.put(key, child);
	}

	public Address getAddress() {
		return address;
	}

	public FidHashQuad getHash() {
		return hash;
	}

	public Collection<FidHashQuad> getParents() {
		return parents.values();
	}

	public Collection<FidHashQuad> getChildren() {
		return children.values();
	}
}
