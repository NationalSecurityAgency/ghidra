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
package ghidra.trace.model.memory;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.Map.Entry;

import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.listing.TraceCodeRegisterSpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceRegisterUtils;

public interface TraceMemoryRegisterSpace extends TraceMemorySpace {
	TraceThread getThread();

	default List<Register> getRegisters() {
		return getThread().getRegisters();
	}

	default void setState(long snap, Register register, TraceMemoryState state) {
		setState(snap, TraceRegisterUtils.rangeForRegister(register), state);
	}

	default TraceMemoryState getState(long snap, Register register) {
		Collection<Entry<TraceAddressSnapRange, TraceMemoryState>> states =
			getStates(snap, register);
		if (states.isEmpty()) {
			return TraceMemoryState.UNKNOWN;
		}
		if (states.size() != 1) {
			throw new IllegalStateException("More than one state is present in " + register);
		}
		return states.iterator().next().getValue();
	}

	default Collection<Entry<TraceAddressSnapRange, TraceMemoryState>> getStates(long snap,
			Register register) {
		return getStates(snap, TraceRegisterUtils.rangeForRegister(register));
	}

	/**
	 * Set the value of a register at the given snap
	 * 
	 * <p>
	 * <b>IMPORTANT:</b> The trace database cannot track the state ({@link TraceMemoryState#KNOWN},
	 * etc.) with per-bit accuracy. It only has byte precision. If the given value specifies, e.g.,
	 * only a single bit, then the entire byte will become marked {@link TraceMemoryState#KNOWN},
	 * even though the remaining 7 bits could technically be unknown.
	 * 
	 * @param snap the snap
	 * @param value the register value
	 * @return the number of bytes written
	 */
	default int setValue(long snap, RegisterValue value) {
		if (!value.hasAnyValue()) {
			return 0;
		}
		Register reg = value.getRegister();
		if (!value.hasValue() || !TraceRegisterUtils.isByteBound(reg)) {
			RegisterValue old = getValue(snap, reg.getBaseRegister());
			// Do not use .getRegisterValue, as that will zero unmasked bits
			// Instead, we'll pass the original register to bufferForValue
			value = old.combineValues(value);
		}
		ByteBuffer buf = TraceRegisterUtils.bufferForValue(reg, value);
		return putBytes(snap, reg.getAddress(), buf);
	}

	/**
	 * Write bytes at the given snap and register address
	 * 
	 * <p>
	 * Note that bit-masked registers are not properly heeded. If the caller wishes to preserve
	 * non-masked bits, it must first retrieve the current value and combine it with the desired
	 * value. The caller must also account for any bit shift in the passed buffer. Alternatively,
	 * consider {@link #setValue(long, RegisterValue)}.
	 * 
	 * @param snap the snap
	 * @param register the register to modify
	 * @param buf the buffer of bytes to write
	 * @return the number of bytes written
	 */
	default int putBytes(long snap, Register register, ByteBuffer buf) {
		int byteLength = register.getNumBytes();
		int limit = buf.limit();
		buf.limit(Math.min(limit, buf.position() + byteLength));
		int result = putBytes(snap, register.getAddress(), buf);
		buf.limit(limit);
		return result;
	}

	default RegisterValue getValue(long snap, Register register) {
		return TraceRegisterUtils.getRegisterValue(register,
			(a, buf) -> getBytes(snap, a, buf));
	}

	default RegisterValue getViewValue(long snap, Register register) {
		return TraceRegisterUtils.getRegisterValue(register,
			(a, buf) -> getViewBytes(snap, a, buf));
	}

	default int getBytes(long snap, Register register, ByteBuffer buf) {
		int byteLength = register.getNumBytes();
		int limit = buf.limit();
		buf.limit(Math.min(limit, buf.position() + byteLength));
		int result = getBytes(snap, register.getAddress(), buf);
		buf.limit(limit);
		return result;
	}

	/**
	 * Remove a value from the given time and register
	 * 
	 * <p>
	 * <b>IMPORANT:</b> The trace database cannot track the state ({@link TraceMemoryState#KNOWN},
	 * etc.) with per-bit accuracy. It only has byte precision. If the given register specifies,
	 * e.g., only a single bit, then the entire byte will become marked
	 * {@link TraceMemoryState#UNKNOWN}, even though the remaining 7 bits could technically be
	 * known.
	 * 
	 * @param snap the snap
	 * @param register the register
	 */
	default void removeValue(long snap, Register register) {
		int byteLength = register.getNumBytes();
		removeBytes(snap, register.getAddress(), byteLength);
	}

	default Collection<RegisterValue> getAllValues(long snap) {
		Set<RegisterValue> result = new LinkedHashSet<>();
		for (Register reg : getRegisters()) {
			result.add(getValue(snap, reg));
		}
		return result;
	}

	@Override
	TraceCodeRegisterSpace getCodeSpace(boolean createIfAbsent);
}
