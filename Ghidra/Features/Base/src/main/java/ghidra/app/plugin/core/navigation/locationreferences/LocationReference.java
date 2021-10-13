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
package ghidra.app.plugin.core.navigation.locationreferences;

import static ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContext.*;

import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.ProgramLocation;

/**
 * A simple container object to provide clients with a reference and an address when both are
 * available.  If no reference exists, then only the {@link #getLocationOfUse()} address is
 * available.
 */
public class LocationReference implements Comparable<LocationReference> {

	private final boolean isOffcutReference;
	private final Address locationOfUseAddress;
	private final String refType;
	private final LocationReferenceContext context;
	private final ProgramLocation location;

	private int hashCode = -1;

	private static String getRefType(Reference r) {
		return r != null ? r.getReferenceType().getName() : "";
	}

	// Note: the address is the location of the item passed to this class. For references, this
	//       represents the 'from' address for a reference; for parameters and variables of a
	//       function, this represents the address of that variable.
	private LocationReference(Address address, ProgramLocation location, String refType,
			LocationReferenceContext context, boolean isOffcut) {
		this.locationOfUseAddress = Objects.requireNonNull(address);
		this.location = location;
		this.refType = refType == null ? "" : refType;
		this.context = context == null ? EMPTY_CONTEXT : context;
		this.isOffcutReference = isOffcut;
	}

	LocationReference(Reference reference, boolean isOffcutReference) {
		this(reference.getFromAddress(), null, getRefType(reference), EMPTY_CONTEXT,
			isOffcutReference);
	}

	LocationReference(Address locationOfUseAddress, String refType, boolean isOffcutReference) {
		this(locationOfUseAddress, null, refType, EMPTY_CONTEXT, isOffcutReference);
	}

	LocationReference(Address locationOfUseAddress) {
		this(locationOfUseAddress, null, null, EMPTY_CONTEXT, false);
	}

	LocationReference(Address locationOfUseAddress, String context) {
		this(locationOfUseAddress, null, null, LocationReferenceContext.get(context), false);
	}

	LocationReference(Address locationOfUseAddress, LocationReferenceContext context) {
		this(locationOfUseAddress, null, null, LocationReferenceContext.get(context), false);
	}

	LocationReference(Address locationOfUseAddress, String context, ProgramLocation location) {
		this(locationOfUseAddress, location, null, LocationReferenceContext.get(context), false);
	}

	/**
	 * Returns the type of reference
	 * @return type of reference or empty string if unknown
	 */
	public String getRefTypeString() {
		return refType;
	}

	/**
	 * Returns true if the corresponding reference is to an offcut address
	 * @return true if offcut
	 */
	public boolean isOffcutReference() {
		return isOffcutReference;
	}

	/**
	 * Returns the address where the item described by this object is used.  For example, for
	 * data types, the address is where a data type is applied; for references, this value is the
	 * <tt>from</tt> address.
	 * 
	 * @return  the address where the item described by this object is used.
	 */
	public Address getLocationOfUse() {
		return locationOfUseAddress;
	}

	/**
	 * Returns the context associated with this location.  This could be a String that highlights
	 * what part of a function signature the location matches or a line from the Decompiler
	 * that matches.
	 * 
	 * @return the context
	 */

	/**
	 * Returns the context associated with this location.  The context may be a simple plain string
	 * or may be String that highlights part of a function signature the location matches or
	 * a line from the Decompiler that matches.
	 * 
	 * @return the context
	 */
	public LocationReferenceContext getContext() {
		return context;
	}

	/**
	 * Returns the program location associated with this reference; may be null.
	 * @return the program location associated with this reference; may be null.
	 */
	public ProgramLocation getProgramLocation() {
		return location;
	}

	@Override
	public int hashCode() {
		if (hashCode != -1) {
			return hashCode;
		}

		final int prime = 31;
		int result = 1;
		result =
			prime * result + ((locationOfUseAddress == null) ? 0 : locationOfUseAddress.hashCode());
		result = prime * result + refType.hashCode();
		hashCode = result;
		return hashCode;
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

		LocationReference other = (LocationReference) obj;
		if (isOffcutReference != other.isOffcutReference) {
			return false;
		}
		if (!context.equals(other.context)) {
			return false;
		}
		if (locationOfUseAddress == null) {
			if (other.locationOfUseAddress != null) {
				return false;
			}
		}
		else if (!locationOfUseAddress.equals(other.locationOfUseAddress)) {
			return false;
		}
		return refType.equals(other.refType);
	}

	@Override
	public int compareTo(LocationReference other) {
		// sort by address only--any duplicate address with different references will be
		// arbitrarily sorted
		return locationOfUseAddress.compareTo(other.locationOfUseAddress);
	}

	@Override
	public String toString() {
		//@formatter:off
		return "{\n" +
			"\taddress: " + locationOfUseAddress + ",\n" +
			((refType.equals("")) ? "" : "\trefType: " + refType + ",\n") +
			"\tisOffcut: " + isOffcutReference + ",\n" +
			((context == EMPTY_CONTEXT) ? "" : "\tcontext: " + context + ",") +
		"}";
		//@formatter:off
	}
}
