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
package ghidra.trace.model.property;

import java.util.Collection;
import java.util.Map;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.trace.model.*;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.util.TraceRegisterUtils;

/**
 * A property map space for a memory space
 *
 * @param <T> the type of values
 */
public interface TracePropertyMapSpace<T> extends TracePropertyMapOperations<T> {
	/**
	 * Get the trace
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Get the address space for this space
	 * 
	 * @return the address space
	 */
	AddressSpace getAddressSpace();

	/**
	 * Set a property on the given register for the given lifespan
	 * 
	 * @param platform the platform defining the register
	 * @param lifespan the range of snaps
	 * @param register the register
	 * @param value the value to set
	 */
	default void set(TracePlatform platform, Lifespan lifespan, Register register, T value) {
		AddressRange range = platform.getConventionalRegisterRange(getAddressSpace(), register);
		set(lifespan, range, value);
	}

	/**
	 * Set a property on the given register for the given lifespan
	 * 
	 * @param lifespan the range of snaps
	 * @param register the register
	 * @param value the value to set
	 */
	default void set(Lifespan lifespan, Register register, T value) {
		set(getTrace().getPlatformManager().getHostPlatform(), lifespan, register, value);
	}

	/**
	 * Get all entries intersecting the given register and lifespan
	 * 
	 * @param lifespan the range of snaps
	 * @param register the register
	 * @return the entries
	 */
	default Collection<Map.Entry<TraceAddressSnapRange, T>> getEntries(Lifespan lifespan,
			Register register) {
		return getEntries(lifespan, TraceRegisterUtils.rangeForRegister(register));
	}

	/**
	 * Remove or truncate entries so that the given box (register and lifespan) contains no entries
	 * 
	 * @param span the range of snaps
	 * @param register the register
	 */
	default void clear(Lifespan span, Register register) {
		clear(span, TraceRegisterUtils.rangeForRegister(register));
	}
}
