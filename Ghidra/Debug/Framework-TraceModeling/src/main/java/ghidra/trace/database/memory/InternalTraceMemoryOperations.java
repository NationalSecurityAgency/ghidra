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
package ghidra.trace.database.memory;

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.Map.Entry;
import java.util.concurrent.locks.ReadWriteLock;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemoryOperations;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.LockHold;

public interface InternalTraceMemoryOperations extends TraceMemoryOperations {

	static TraceMemoryState requireOne(
			Collection<Entry<TraceAddressSnapRange, TraceMemoryState>> states, Register register) {
		if (states.isEmpty()) {
			return TraceMemoryState.UNKNOWN;
		}
		if (states.size() != 1) {
			throw new IllegalStateException("More than one state is present in " + register);
		}
		return states.iterator().next().getValue();
	}

	/**
	 * For register mapping conventions
	 * 
	 * @return the address space
	 */
	AddressSpace getSpace();

	ReadWriteLock getLock();

	@Override
	default void setState(TracePlatform platform, long snap, Register register,
			TraceMemoryState state) {
		AddressRange range = platform.getConventionalRegisterRange(getSpace(), register);
		setState(snap, range, state);
	}

	@Override
	default TraceMemoryState getState(TracePlatform platform, long snap, Register register) {
		AddressRange range = platform.getConventionalRegisterRange(getSpace(), register);
		return requireOne(getStates(snap, range), register);
	}

	@Override
	default Collection<Entry<TraceAddressSnapRange, TraceMemoryState>> getStates(
			TracePlatform platform, long snap, Register register) {
		AddressRange range = platform.getConventionalRegisterRange(getSpace(), register);
		return getStates(snap, range);
	}

	@Override
	default int putBytes(TracePlatform platform, long snap, Register register, ByteBuffer buf) {
		AddressRange range = platform.getConventionalRegisterRange(getSpace(), register);
		int byteLength = (int) range.getLength();
		int limit = buf.limit();
		buf.limit(Math.min(limit, buf.position() + byteLength));
		int result = putBytes(snap, range.getMinAddress(), buf);
		buf.limit(limit);
		return result;
	}

	@Override
	default int setValue(TracePlatform platform, long snap, RegisterValue value) {
		if (!value.hasAnyValue()) {
			return 0;
		}
		try (LockHold hold = LockHold.lock(getLock().writeLock())) {
			Register register = value.getRegister();
			AddressRange range = platform.getConventionalRegisterRange(getSpace(), register);
			if (!value.hasValue() || !TraceRegisterUtils.isByteBound(register)) {
				// Don't try to inline to keep range. Base register may have different range
				RegisterValue old = getValue(platform, snap, register.getBaseRegister());
				// Do not use .getRegisterValue, as that will zero unmasked bits
				// Instead, we'll pass the original register to bufferForValue
				value = old.combineValues(value);
			}
			ByteBuffer buf = TraceRegisterUtils.bufferForValue(register, value);
			return putBytes(snap, range.getMinAddress(), buf);
		}
	}

	@Override
	default RegisterValue getValue(TracePlatform platform, long snap, Register register) {
		ByteBuffer buf = TraceRegisterUtils.prepareBuffer(register);
		AddressRange range = platform.getConventionalRegisterRange(getSpace(), register);
		getBytes(snap, range.getMinAddress(), buf);
		return TraceRegisterUtils.finishBuffer(buf, register);
	}

	@Override
	default RegisterValue getViewValue(TracePlatform platform, long snap, Register register) {
		ByteBuffer buf = TraceRegisterUtils.prepareBuffer(register);
		AddressRange range = platform.getConventionalRegisterRange(getSpace(), register);
		getViewBytes(snap, range.getMinAddress(), buf);
		return TraceRegisterUtils.finishBuffer(buf, register);
	}

	@Override
	default int getBytes(TracePlatform platform, long snap, Register register, ByteBuffer buf) {
		AddressRange range = platform.getConventionalRegisterRange(getSpace(), register);
		int byteLength = (int) range.getLength();
		int limit = buf.limit();
		buf.limit(Math.min(limit, buf.position() + byteLength));
		int result = getBytes(snap, range.getMinAddress(), buf);
		buf.limit(limit);
		return result;
	}

	@Override
	default void removeValue(TracePlatform platform, long snap, Register register) {
		AddressRange range = platform.getConventionalRegisterRange(getSpace(), register);
		removeBytes(snap, range.getMinAddress(), (int) range.getLength());
	}
}
