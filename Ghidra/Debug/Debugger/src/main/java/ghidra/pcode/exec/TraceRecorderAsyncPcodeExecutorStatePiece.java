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
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.trace.DirectBytesTracePcodeExecutorStatePiece;
import ghidra.pcode.exec.trace.TraceMemoryStatePcodeExecutorStatePiece;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.task.TaskMonitor;

/**
 * An executor state which can asynchronously read and write a live target, if applicable
 * 
 * <p>
 * This is used for executing Sleigh code to manipulate trace history or a live target.
 * 
 * <p>
 * TODO: It might be easier to re-factor this to operate synchronously, executing Sleigh programs in
 * a separate thread.
 */
public class TraceRecorderAsyncPcodeExecutorStatePiece
		extends AsyncWrappedPcodeExecutorStatePiece<byte[], byte[]> {
	private final TraceRecorder recorder;
	private final DirectBytesTracePcodeExecutorStatePiece traceState;
	private final TraceMemoryStatePcodeExecutorStatePiece traceMemState;

	public TraceRecorderAsyncPcodeExecutorStatePiece(TraceRecorder recorder, long snap,
			TraceThread thread, int frame) {
		super(
			new DirectBytesTracePcodeExecutorStatePiece(recorder.getTrace(), snap, thread, frame));
		this.recorder = recorder;
		this.traceState = (DirectBytesTracePcodeExecutorStatePiece) state;
		this.traceMemState =
			new TraceMemoryStatePcodeExecutorStatePiece(recorder.getTrace(), snap, thread, frame);
	}

	protected CompletableFuture<?> doSetTargetVar(AddressSpace space, long offset, int size,
			boolean quantize, byte[] val) {
		return recorder.writeVariable(traceState.getThread(), 0, space.getAddress(offset), val);
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
			int size, boolean quantize) {
		if (space.isMemorySpace()) {
			Address addr = space.getAddress(quantizeOffset(space, offset));
			AddressSet set = new AddressSet(addr, space.getAddress(offset + size - 1));
			CompletableFuture<NavigableMap<Address, byte[]>> future =
				recorder.readMemoryBlocks(set, TaskMonitor.DUMMY, true);
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
				return state.getVar(space, offset, size, quantize);
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
			CompletableFuture<byte[]> offset, int size, boolean quantize,
			CompletableFuture<byte[]> val) {
		if (!isTargetSpace(space)) {
			return super.doSetVar(space, offset, size, quantize, val);
		}
		return offset.thenCompose(off -> val.thenCompose(v -> {
			long lOff = traceState.getAddressArithmetic().toLong(off, Purpose.STORE);
			return doSetTargetVar(space, lOff, size, quantize, v);
		}));
	}

	@Override
	protected CompletableFuture<byte[]> doGetVar(AddressSpace space,
			CompletableFuture<byte[]> offset, int size, boolean quantize) {
		if (!isTargetSpace(space)) {
			return super.doGetVar(space, offset, size, quantize);
		}
		return offset.thenCompose(off -> {
			TraceMemoryState ms = traceMemState.getVar(space, off, size, quantize);
			if (ms == TraceMemoryState.KNOWN) {
				return super.doGetVar(space, offset, size, quantize);
			}
			long lOff = traceState.getAddressArithmetic().toLong(off, Purpose.LOAD);
			return doGetTargetVar(space, lOff, size, quantize);
		});
	}
}
