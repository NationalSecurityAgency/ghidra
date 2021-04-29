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

	default int setValue(long snap, RegisterValue value) {
		ByteBuffer buf = TraceRegisterUtils.bufferForValue(value);
		return putBytes(snap, value.getRegister().getAddress(), buf);
	}

	default int putBytes(long snap, Register register, ByteBuffer buf) {
		int byteLength = TraceRegisterUtils.byteLengthOf(register);
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
		int byteLength = TraceRegisterUtils.byteLengthOf(register);
		int limit = buf.limit();
		buf.limit(Math.min(limit, buf.position() + byteLength));
		int result = getBytes(snap, register.getAddress(), buf);
		buf.limit(limit);
		return result;
	}

	default void removeValue(long snap, Register register) {
		int byteLength = TraceRegisterUtils.byteLengthOf(register);
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
