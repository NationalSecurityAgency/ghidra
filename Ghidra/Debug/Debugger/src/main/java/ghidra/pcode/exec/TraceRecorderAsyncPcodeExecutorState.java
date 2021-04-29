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
package ghidra.pcode.exec;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import ghidra.app.services.TraceRecorder;
import ghidra.pcode.exec.trace.TraceBytesPcodeExecutorState;
import ghidra.pcode.exec.trace.TraceMemoryStatePcodeExecutorStatePiece;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.trace.model.memory.TraceMemoryRegisterSpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.task.TaskMonitor;

public class TraceRecorderAsyncPcodeExecutorState
		extends AsyncWrappedPcodeExecutorState<byte[]> {
	private final TraceRecorder recorder;
	private final TraceBytesPcodeExecutorState traceState;
	private final TraceMemoryStatePcodeExecutorStatePiece traceMemState;

	public TraceRecorderAsyncPcodeExecutorState(TraceRecorder recorder, long snap,
			TraceThread thread, int frame) {
		super(new TraceBytesPcodeExecutorState(recorder.getTrace(), snap, thread, frame));
		this.recorder = recorder;
		this.traceState = (TraceBytesPcodeExecutorState) state;
		this.traceMemState =
			new TraceMemoryStatePcodeExecutorStatePiece(recorder.getTrace(), snap, thread, frame);
	}

	protected CompletableFuture<?> doSetTargetVar(AddressSpace space, long offset, int size,
			boolean truncateAddressableUnit, byte[] val) {
		if (space.isMemorySpace()) {
			return recorder.writeProcessMemory(space.getAddress(offset), val);
		}
		assert space.isRegisterSpace();

		Language lang = recorder.getTrace().getBaseLanguage();
		Register register = lang.getRegister(space, offset, size);
		if (register == null) {
			// TODO: Is this too restrictive? I can't imagine any code producing such nonsense
			throw new IllegalArgumentException(
				"write to register space must be to one register");
		}

		RegisterValue rv = new RegisterValue(register, Utils.bytesToBigInteger(
			val, size, recorder.getTrace().getBaseLanguage().isBigEndian(), false));
		TraceMemoryRegisterSpace regs = recorder.getTrace()
				.getMemoryManager()
				.getMemoryRegisterSpace(traceState.getThread(), false);
		rv = TraceRegisterUtils.combineWithTraceBaseRegisterValue(rv, traceState.getSnap(),
			regs, true);
		return recorder.writeThreadRegisters(traceState.getThread(), traceState.getFrame(),
			Map.of(rv.getRegister(), rv));
	}

	protected byte[] knitFromResults(NavigableMap<Address, byte[]> map, Address addr, int size) {
		Address floor = map.floorKey(addr);
		NavigableMap<Address, byte[]> tail;
		if (floor == null) {
			tail = map;
		}
		else {
			tail = map.tailMap(floor, true);
		}
		byte[] result = new byte[size];
		for (Map.Entry<Address, byte[]> ent : tail.entrySet()) {
			long off = ent.getKey().subtract(addr);
			if (off >= size || off < 0) {
				break;
			}
			int subSize = Math.min(size - (int) off, ent.getValue().length);
			System.arraycopy(ent.getValue(), 0, result, (int) off, subSize);
		}
		return result;
	}

	protected CompletableFuture<byte[]> doGetTargetVar(AddressSpace space, long offset,
			int size, boolean truncateAddressableUnit) {
		if (space.isMemorySpace()) {
			Address addr = space.getAddress(truncateOffset(space, offset));
			AddressSet set = new AddressSet(addr, space.getAddress(offset + size - 1));
			CompletableFuture<NavigableMap<Address, byte[]>> future =
				recorder.captureProcessMemory(set, TaskMonitor.DUMMY);
			return future.thenApply(map -> {
				return knitFromResults(map, addr, size);
			});
		}
		assert space.isRegisterSpace();

		Language lang = recorder.getTrace().getBaseLanguage();
		Register register = lang.getRegister(space, offset, size);
		if (register == null) {
			// TODO: Is this too restrictive?
			throw new IllegalArgumentException(
				"read from register space must be from one register");
		}
		Register baseRegister = register.getBaseRegister();

		CompletableFuture<Map<Register, RegisterValue>> future =
			recorder.captureThreadRegisters(traceState.getThread(), traceState.getFrame(),
				Set.of(baseRegister));
		return future.thenApply(map -> {
			RegisterValue baseVal = map.get(baseRegister);
			if (baseVal == null) {
				return state.getVar(space, offset, size, truncateAddressableUnit);
			}
			BigInteger val = baseVal.getRegisterValue(register).getUnsignedValue();
			return Utils.bigIntegerToBytes(val, size,
				recorder.getTrace().getBaseLanguage().isBigEndian());
		});
	}

	protected boolean isTargetSpace(AddressSpace space) {
		return traceState.getSnap() == recorder.getSnap() && !space.isConstantSpace() &&
			!space.isUniqueSpace();
	}

	@Override
	protected CompletableFuture<?> doSetVar(AddressSpace space,
			CompletableFuture<byte[]> offset, int size, boolean truncateAddressableUnit,
			CompletableFuture<byte[]> val) {
		if (!isTargetSpace(space)) {
			return super.doSetVar(space, offset, size, truncateAddressableUnit, val);
		}
		return offset.thenCompose(off -> val.thenCompose(v -> {
			return doSetTargetVar(space, traceState.offsetToLong(off), size,
				truncateAddressableUnit, v);
		}));
	}

	@Override
	protected CompletableFuture<byte[]> doGetVar(AddressSpace space,
			CompletableFuture<byte[]> offset, int size, boolean truncateAddressableUnit) {
		if (!isTargetSpace(space)) {
			return super.doGetVar(space, offset, size, truncateAddressableUnit);
		}
		return offset.thenCompose(off -> {
			TraceMemoryState ms = traceMemState.getVar(space, off, size, truncateAddressableUnit);
			if (ms == TraceMemoryState.KNOWN) {
				return super.doGetVar(space, offset, size, truncateAddressableUnit);
			}
			return doGetTargetVar(space, traceState.offsetToLong(off), size,
				truncateAddressableUnit);
		});
	}
}
