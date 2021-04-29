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
package ghidra.trace.model.listing;

import java.util.HashSet;
import java.util.Set;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.lang.Register;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceRegisterUtils;

/**
 * A {@link TraceBaseCodeUnitsView} associated with a thread, restricted to register space, and
 * possibly restricted to a particular subset by type.
 * 
 * @param <T> the type of units in the view
 */
public interface TraceBaseCodeUnitsRegisterView<T extends TraceCodeUnit>
		extends TraceBaseCodeUnitsView<T> {

	/**
	 * Get the associated thread
	 * 
	 * @return the thread
	 */
	TraceThread getThread();

	/**
	 * Get the set of registers for the trace's base language
	 * 
	 * @return the register set
	 */
	default Set<Register> getRegisters() {
		return new HashSet<>(getThread().getTrace().getBaseLanguage().getRegisters());
	}

	/**
	 * Get the unit (or component of a structure) which spans exactly the addresses of the given
	 * register
	 * 
	 * @param register the register
	 * @return the unit or {@code null}
	 */
	@SuppressWarnings("unchecked")
	default T getForRegister(long snap, Register register) {
		// Find a code unit which contains the register completely
		T candidate = getContaining(snap, register.getAddress());
		if (candidate == null) {
			return null;
		}
		AddressRange range = TraceRegisterUtils.rangeForRegister(register);
		int cmpMax = range.getMaxAddress().compareTo(candidate.getMaxAddress());
		if (cmpMax > 0) {
			return null;
		}
		if (cmpMax == 0 && candidate.getMinAddress().equals(register.getAddress())) {
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

	/**
	 * Get the unit which completely contains the given register
	 * 
	 * This does not descend into structures.
	 * 
	 * @param register the register
	 * @return the unit or {@code unit}
	 */
	default T getContaining(long snap, Register register) {
		T candidate = getContaining(snap, register.getAddress());
		if (candidate == null) {
			return null;
		}
		AddressRange range = TraceRegisterUtils.rangeForRegister(register);
		int cmpMax = range.getMaxAddress().compareTo(candidate.getMaxAddress());
		if (cmpMax > 0) {
			return null;
		}
		return candidate;
	}

	/**
	 * Get the live units whose start addresses are within the given register
	 * 
	 * @param register the register
	 * @param forward true to order the units by increasing address, false for descending
	 * @return the iterable of units
	 */
	default Iterable<? extends T> get(long snap, Register register, boolean forward) {
		return get(snap, TraceRegisterUtils.rangeForRegister(register), forward);
	}
}
