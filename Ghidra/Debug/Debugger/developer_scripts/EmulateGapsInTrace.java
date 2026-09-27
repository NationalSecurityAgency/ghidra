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
//EXPERIMENTAL script that emulates instructions between snapshots in a sparse trace
//@category Debugger
//@keybinding
//@menupath
//@toolbar

import java.nio.ByteBuffer;
import java.util.*;

import db.Transaction;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerEmulationIntegration;
import ghidra.app.plugin.core.debug.service.emulation.Mode;
import ghidra.app.plugin.core.debug.service.emulation.data.DefaultPcodeDebuggerAccess;
import ghidra.app.script.GhidraScript;
import ghidra.debug.flatapi.FlatDebuggerAPI;
import ghidra.pcode.emu.*;
import ghidra.pcode.exec.BytesPcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.trace.TraceEmulationIntegration;
import ghidra.pcode.exec.trace.data.PcodeTraceAccess;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectManager;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

import static ghidra.pcode.exec.BytesPcodeArithmetic.forLanguage;

public class EmulateGapsInTrace extends GhidraScript implements FlatDebuggerAPI {
	private static class CustomWriter extends TraceEmulationIntegration.TraceWriter {
		final Map<Address, Integer> readMap = new HashMap<>();
		final Map<Address, Integer> writeMap = new HashMap<>();
		final BytesPcodeArithmetic arithmetic;
		SleighInstructionDecoder decoder = null;

		public CustomWriter(PcodeTraceAccess access, Language language) {
			super(access);
			arithmetic = forLanguage(language);
		}

		@Override
		public void beforeLoad(PcodeThread<Object> thread, PcodeOp op, AddressSpace space,
				Object offset, int size) {
			if (offset instanceof byte[] off) {
				readMap.put(arithmetic.toAddress(off, space, PcodeArithmetic.Purpose.INSPECT),
						size);
			}
			super.beforeLoad(thread, op, space, offset, size);
		}

		@Override
		public void beforeStore(PcodeThread<Object> thread, PcodeOp op, AddressSpace space,
				Object offset, int size, Object value) {
			if (offset instanceof byte[] off) {
				writeMap.put(arithmetic.toAddress(off, space, PcodeArithmetic.Purpose.INSPECT),
						size);
			}
			super.beforeStore(thread, op, space, offset, size, value);
		}
	}

	@Override
	protected void run() throws Exception {
		final Trace fromTrace = requireCurrentTrace();
		final TraceThread fromThread = requireCurrentThread();
		Iterator<? extends TraceSnapshot> iterator = fromTrace.getTimeManager()
				.getSnapshots(getCurrentSnap(), true, fromTrace.getTimeManager().getMaxSnap(),
						true)
				.iterator();

		TraceSnapshot cur = iterator.next();
		Trace toTrace = new DBTrace("%s Emulated Gaps".formatted(fromTrace.getName()),
				fromTrace.getBaseCompilerSpec(), this);
		final TraceObjectManager om = toTrace.getObjectManager();

		try (Transaction ignored = toTrace.openTransaction("Emulate the gaps");
				TraceObjectManager.BypassWriteCache ignored1 = om.withoutWriteCache()) {
			om.createRootObject(fromTrace.getObjectManager().getRootSchema());

			monitor.initialize(fromTrace.getTimeManager().getMaxSnap() - getCurrentSnap());
			while (iterator.hasNext()) {
				monitor.increment();
				TraceSnapshot next = iterator.next();

				TraceThread toThread = copySnapshotToTrace(cur, toTrace);

				if (emulateToNextSnapshot(cur, fromThread, fromTrace, toTrace, toThread, next)) {
					break;
				}
				cur = next;
			}
			activateTrace(toTrace);
		}
		catch (Exception e) {
			activateTrace(toTrace);
			throw e;
		}
	}

	private TraceThread copySnapshotToTrace(TraceSnapshot fromSnapshot, Trace toTrace) {
		TraceSnapshot snapshot =
				toTrace.getTimeManager().createSnapshot(fromSnapshot.getDescription());
		Trace fromTrace = fromSnapshot.getTrace();
		TraceThread fromThread = fromSnapshot.getEventThread();

		fromTrace.getObjectManager()
				.getAllObjects()
				.filter(o -> o.getLife().contains(fromSnapshot.getKey()) && !o.isRoot())
				.forEachOrdered(fromTraceObject -> {
					TraceObject toTraceObject = toTrace.getObjectManager()
							.createObject(fromTraceObject.getCanonicalPath());
					toTraceObject.insert(Lifespan.nowOn(snapshot.getKey()),
							TraceObject.ConflictResolution.DENY);
					fromTraceObject.getValues(Lifespan.at(fromSnapshot.getKey()))
							.forEach(fromTraceObjectValue -> {
								if (!(fromTraceObjectValue.getValue() instanceof TraceObject)) {
									toTraceObject.setValue(Lifespan.nowOn(snapshot.getKey()),
											fromTraceObjectValue.getEntryKey(),
											fromTraceObjectValue.getValue());
								}
							});
				});

		TraceThread thread = toTrace.getThreadManager().getThread(fromThread.getKey());
		snapshot.setEventThread(thread);

		for (AddressRange addressRange : fromTrace.getMemoryManager()
				.getAddressesWithState(fromSnapshot.getKey(),
						s -> s != TraceMemoryState.UNKNOWN)) {
			ByteBuffer buffer = ByteBuffer.allocate((int) addressRange.getLength());
			fromTrace.getMemoryManager()
					.getBytes(fromSnapshot.getKey(), addressRange.getMinAddress(), buffer);
			buffer.flip();
			if (addressRange.getMinAddress().isRegisterAddress()) {
				Address regAddress = toTrace.getMemoryManager()
						.getMemoryRegisterSpace(thread, true)
						.getAddressSpace()
						.getAddress(addressRange.getMinAddress().getOffset());
				toTrace.getMemoryManager()
						.getMemoryRegisterSpace(thread, true)
						.putBytes(snapshot.getKey(), regAddress, buffer);
			}
			else {
				toTrace.getMemoryManager()
						.putBytes(snapshot.getKey(), toTrace.getBaseAddressFactory()
								.getDefaultAddressSpace()
								.getAddress(addressRange.getMinAddress().getOffset()), buffer);
			}
		}

		return thread;
	}

	private boolean emulateToNextSnapshot(TraceSnapshot curFromSnapshot, TraceThread fromThread,
			Trace fromTrace, Trace toTrace, TraceThread toThread, TraceSnapshot nextFromSnapshot) {
		Register programCounter = fromTrace.getBaseLanguage().getProgramCounter();

		TraceMemorySpace registerSpace =
				fromTrace.getMemoryManager().getMemoryRegisterSpace(fromThread, false);

		RegisterValue endPCValue =
				registerSpace.getViewValue(nextFromSnapshot.getKey(), programCounter);

		int tickCount = 1;
		TraceSchedule schedule = TraceSchedule.snap(curFromSnapshot.getKey())
				.steppedForward(fromThread, tickCount++);

//		TraceEmulationIntegration.Writer writer =
//				DebuggerEmulationIntegration.bytesDelayedWriteTrace(
//						new DefaultPcodeDebuggerAccess(getState().getTool(), null,
//								fromTrace.getPlatformManager().getHostPlatform(),
//								curFromSnapshot.getKey()));

		var writer = new CustomWriter(new DefaultPcodeDebuggerAccess(getState().getTool(), null,
				fromTrace.getPlatformManager().getHostPlatform(), curFromSnapshot.getKey()),
				fromTrace.getBaseLanguage());
		writer.putHandler(new DebuggerEmulationIntegration.TargetBytesPieceHandler(Mode.RO));

		PcodeEmulator emulator = new PcodeEmulator(fromTrace.getBaseLanguage(), writer.callbacks());

		PcodeThread<byte[]> pcodeThread = emulator.getThread(fromThread.getPath(), true);
//		ThreadPcodeExecutorState<byte[]> state = pcodeThread.getState();
//		for (Register register : fromTrace.getBaseLanguage().getRegisters()) {
//			if (!register.isBaseRegister()) {
//				continue;
//			}
//			RegisterValue value = fromTrace.getMemoryManager()
//					.getMemoryRegisterSpace(fromThread, true)
//					.getValue(curFromSnapshot.getKey(), register);
//			state.setRegisterValue(register, value);
//		}

		try {
			while (true) {
				monitor.checkCancelled();
				pcodeThread.stepInstruction();
				if (pcodeThread.getCounter().getOffset() ==
				    endPCValue.getUnsignedValue().longValue()) {
					break;
				}

				TraceSnapshot snapshot =
						toTrace.getTimeManager().createSnapshot("Emulated " + schedule);
				Msg.info(this, "Snapshot %d".formatted(snapshot.getKey()));
				snapshot.setSchedule(schedule);
				snapshot.setEventThread(toThread);
				TraceStackFrame frame = toTrace.getStackManager()
						.getStack(toThread, snapshot.getKey(), true)
						.getFrame(snapshot.getKey(), 0, true);
				frame.setProgramCounter(Lifespan.nowOn(snapshot.getKey()),
						pcodeThread.getCounter());
				writer.writeDown(new DefaultPcodeDebuggerAccess(getState().getTool(), null,
						toTrace.getPlatformManager().getHostPlatform(), snapshot.getKey()));
				for (Map.Entry<Address, Integer> entry : writer.readMap.entrySet()) {
					AddressRangeImpl range = new AddressRangeImpl(entry.getKey(),
							entry.getValue());
					toTrace.getReferenceManager()
							.addMemoryReference(Lifespan.at(snapshot.getKey() - 1),
									addr(toTrace, pcodeThread.getCounter().getOffset()), range,
									RefType.READ, SourceType.USER_DEFINED, -1);
				}

				for (Map.Entry<Address, Integer> entry : writer.writeMap.entrySet()) {
					AddressRangeImpl range = new AddressRangeImpl(entry.getKey(),
							entry.getValue());
					toTrace.getReferenceManager()
							.addMemoryReference(Lifespan.at(snapshot.getKey() - 1),
									addr(toTrace, pcodeThread.getCounter().getOffset()), range,
									RefType.WRITE, SourceType.USER_DEFINED, -1);
				}

				writer.readMap.clear();
				writer.writeMap.clear();
				schedule = TraceSchedule.snap(curFromSnapshot.getKey())
						.steppedForward(fromThread, tickCount++);
			}
		}
		catch (CancelledException _) {
			return true;
		}
		catch (Exception e) {
			printerr(e.getMessage());
		}
		return false;
	}

	Address addr(Trace trace, long addr) {
		return trace.getBaseAddressFactory().getDefaultAddressSpace().getAddress(addr);
	}
}
