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
package ghidra.util.table.field;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;

/**
 * An object that is one end of a {@link Reference}.  This is used by table models that want to
 * show all references from one location to many other locations or models that wish to 
 * show all references to one location from many other locations.
 */
public abstract class ReferenceEndpoint {

	private final Reference reference;
	private final Address address;
	private final RefType refType;
	private final boolean isOffcut;
	private final SourceType source;

	protected ReferenceEndpoint(Reference reference, Address address, RefType refType,
			boolean isOffcut, SourceType source) {
		this.reference = reference;
		this.address = address;
		this.refType = refType;
		this.isOffcut = isOffcut;
		this.source = source;
	}

	public Address getAddress() {
		return address;
	}

	public Reference getReference() {
		return reference;
	}

	public boolean isOffcut() {
		return isOffcut;
	}

	public RefType getReferenceType() {
		return refType;
	}

	public SourceType getSource() {
		return source;
	}
}
