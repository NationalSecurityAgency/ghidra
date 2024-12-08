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
package ghidra.trace.database.target;

import ghidra.program.model.address.*;
import ghidra.trace.model.Lifespan;
import ghidra.util.database.spatial.BoundedShape;

public interface ValueShape extends BoundedShape<ValueBox> {
	DBTraceObject getParent();

	DBTraceObject getChild();

	DBTraceObject getChildOrNull();

	String getEntryKey();

	Lifespan getLifespan();

	/**
	 * If the value is an address or range, the id of the address space
	 * 
	 * @return the space id, or -1 for non-address value
	 */
	int getAddressSpaceId();

	long getMinAddressOffset();

	long getMaxAddressOffset();

	default Address getMinAddress(AddressFactory factory) {
		int spaceId = getAddressSpaceId();
		if (spaceId == -1) {
			return null;
		}
		AddressSpace space = factory.getAddressSpace(spaceId);
		return space.getAddress(getMinAddressOffset());
	}

	default Address getMaxAddress(AddressFactory factory) {
		int spaceId = getAddressSpaceId();
		if (spaceId == -1) {
			return null;
		}
		AddressSpace space = factory.getAddressSpace(spaceId);
		return space.getAddress(getMaxAddressOffset());
	}

	default AddressRange getRange(AddressFactory factory) {
		Address min = getMinAddress(factory);
		if (min == null) {
			return null;
		}
		return new AddressRangeImpl(min, getMaxAddress(factory));
	}
}
