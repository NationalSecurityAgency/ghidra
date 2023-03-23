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
package ghidra.trace.database.space;

import ghidra.program.model.address.*;

public interface DBTraceSpaceBased extends DBTraceSpaceKey {

	default boolean isMySpace(AddressSpace space) {
		if (space == getAddressSpace()) {
			return true;
		}
		/**
		 * This turned out to be a bad idea! Every place a client gives an address would have to be
		 * translated into the overlay space first. Every manager, every method. It's a lot. For
		 * now, I'll leave that burden on the client. Especially, since the register overlay spaces
		 * will all be delegated from the manger directly, it doesn't make sense to permit sloppy
		 * access.
		 */
		/*if (space.isRegisterSpace() && space == getAddressSpace().getPhysicalSpace()) {
			return true;
		}*/
		return false;
	}

	default String explainLanguages(AddressSpace space) {
		if (space.getName().equals(getAddressSpace().getName())) {
			return ". It's likely they come from different languages. Check the platform.";
		}
		return "";
	}

	default long assertInSpace(Address addr) {
		if (!isMySpace(addr.getAddressSpace())) {
			throw new IllegalArgumentException(
				"Address '" + addr + "' is not in this space: '" + getAddressSpace() + "'" +
					explainLanguages(addr.getAddressSpace()));
		}
		return addr.getOffset();
	}

	default void assertInSpace(AddressRange range) {
		if (!isMySpace(range.getAddressSpace())) {
			throw new IllegalArgumentException(
				"Address Range '" + range + "' is not in this space: '" + getAddressSpace() + "'" +
					explainLanguages(range.getAddressSpace()));
		}
	}

	default Address toOverlay(Address physical) {
		return getAddressSpace().getOverlayAddress(physical);
	}

	default Address toAddress(long offset) {
		return getAddressSpace().getAddress(offset);
	}

	void invalidateCache();
}
