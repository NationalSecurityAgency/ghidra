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
package ghidra.trace.database.listing;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.listing.*;
import ghidra.trace.util.TraceRegisterUtils;

public interface InternalBaseCodeUnitsView<T extends TraceCodeUnit>
		extends TraceBaseCodeUnitsView<T> {
	AddressSpace getSpace();

	@Override
	@SuppressWarnings("unchecked")
	default T getForRegister(TracePlatform platform, long snap, Register register) {
		// Find a code unit which contains the register completely
		AddressRange range = platform.getConventionalRegisterRange(getSpace(), register);
		T candidate = getContaining(snap, range.getMinAddress());
		if (candidate == null) {
			return null;
		}
		int cmpMax = range.getMaxAddress().compareTo(candidate.getMaxAddress());
		if (cmpMax > 0) {
			return null;
		}
		if (cmpMax == 0 && candidate.getMinAddress().equals(range.getMinAddress())) {
			return candidate;
		}
		if (!(candidate instanceof TraceData)) {
			return null;
		}
		TraceData data = (TraceData) candidate;
		// Cast because if candidate is TraceData, T is, too
		// NOTE: It may not be a primitive
		return (T) TraceRegisterUtils.seekComponent(data, range);
	}

	@Override
	default T getContaining(TracePlatform platform, long snap, Register register) {
		AddressRange range = platform.getConventionalRegisterRange(getSpace(), register);
		T candidate = getContaining(snap, range.getMinAddress());
		if (candidate == null) {
			return null;
		}
		int cmpMax = range.getMaxAddress().compareTo(candidate.getMaxAddress());
		if (cmpMax > 0) {
			return null;
		}
		return candidate;
	}
}
