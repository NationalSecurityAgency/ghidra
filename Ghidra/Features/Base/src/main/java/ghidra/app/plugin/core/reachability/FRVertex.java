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
package ghidra.app.plugin.core.reachability;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.util.SystemUtilities;

import java.util.*;

import org.apache.commons.collections4.Factory;
import org.apache.commons.collections4.map.LazyMap;


class FRVertex {

	private Factory<List<CodeBlockReference>> factory = new Factory<List<CodeBlockReference>>() {
		@Override
		public List<CodeBlockReference> create() {
			return new ArrayList<>();
		}
	};
	private Map<FRVertex, List<CodeBlockReference>> incomingReferences = LazyMap.lazyMap(
		new HashMap<FRVertex, List<CodeBlockReference>>(), factory);

	private Address address;

	FRVertex(Address address) {
		this.address = address;
	}

	void addReference(FRVertex referent, CodeBlockReference reference) {
		List<CodeBlockReference> refs = incomingReferences.get(referent);
		refs.add(reference);
	}

	CodeBlockReference getReference(FRVertex referent) {
		List<CodeBlockReference> refs = incomingReferences.get(referent);
		for (CodeBlockReference ref : refs) {
			Address destination = ref.getDestinationAddress();
			if (address.equals(destination)) {
				return ref;
			}
		}
		return null;
	}

	@Override
	public String toString() {
		return address.toString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((address == null) ? 0 : address.hashCode());
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

		FRVertex other = (FRVertex) obj;
		return SystemUtilities.isEqual(address, other.address);
	}

	Address getAddress() {
		return address;
	}

}
