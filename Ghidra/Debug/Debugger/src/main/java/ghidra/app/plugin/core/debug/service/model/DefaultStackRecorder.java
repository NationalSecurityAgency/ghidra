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
package ghidra.app.plugin.core.debug.service.model;

import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.plugin.core.debug.mapping.DebuggerMemoryMapper;
import ghidra.app.plugin.core.debug.service.model.interfaces.ManagedStackRecorder;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetStackFrame;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.trace.model.Trace;
import ghidra.trace.model.stack.*;
import ghidra.trace.model.thread.TraceThread;

public class DefaultStackRecorder implements ManagedStackRecorder {

	protected static int getFrameLevel(TargetStackFrame frame) {
		// TODO: A fair assumption? frames are elements with numeric base-10 indices
		return Integer.decode(frame.getIndex());
	}

	private NavigableMap<Integer, TargetStackFrame> stack =
		Collections.synchronizedNavigableMap(new TreeMap<>());

	private final TraceThread thread;
	private final DefaultTraceRecorder recorder;
	private final Trace trace;
	private final TraceStackManager stackManager;

	public DefaultStackRecorder(TraceThread thread, DefaultTraceRecorder recorder) {
		this.thread = thread;
		this.recorder = recorder;
		this.trace = recorder.getTrace();
		this.stackManager = trace.getStackManager();
	}

	@Override
	public void offerStackFrame(TargetStackFrame frame) {
		recordFrame(frame);
	}

	@Override
	public void recordStack() {
		long snap = recorder.getSnap();
		DebuggerMemoryMapper mm = recorder.getMemoryMapper();
		Map<Integer, Address> pcsByLevel;
		synchronized (stack) {
			pcsByLevel = stack.entrySet()
					.stream()
					.collect(Collectors.toMap(e -> e.getKey(), e -> {
						return mm.targetToTrace(e.getValue().getProgramCounter());
					}));
		}
		recorder.parTx.execute("Stack changed", () -> {
			TraceStack traceStack = stackManager.getStack(thread, snap, true);
			traceStack.setDepth(stackDepth(), false);
			for (Map.Entry<Integer, Address> ent : pcsByLevel.entrySet()) {
				doRecordFrame(traceStack, ent.getKey(), ent.getValue());
			}
		}, thread.getPath());
	}

	public void popStack() {
		long snap = recorder.getSnap();
		recorder.parTx.execute("Stack popped", () -> {
			TraceStack traceStack = stackManager.getStack(thread, snap, true);
			traceStack.setDepth(stackDepth(), false);
		}, thread.getPath());
	}

	public void doRecordFrame(TraceStack traceStack, int frameLevel, Address pc) {
		TraceStackFrame traceFrame = traceStack.getFrame(frameLevel, true);
		traceFrame.setProgramCounter(pc);
	}

	public void recordFrame(TargetStackFrame frame) {
		long snap = recorder.getSnap();
		synchronized (stack) {
			stack.put(getFrameLevel(frame), frame);
		}
		recorder.parTx.execute("Stack frame added", () -> {
			DebuggerMemoryMapper memoryMapper = recorder.getMemoryMapper();
			if (memoryMapper == null) {
				return;
			}
			Address pc = frame.getProgramCounter();
			Address tracePc = pc == null ? null : memoryMapper.targetToTrace(pc);
			TraceStack traceStack = stackManager.getStack(thread, snap, true);
			doRecordFrame(traceStack, getFrameLevel(frame), tracePc);
		}, thread.getPath());
	}

	protected int stackDepth() {
		synchronized (stack) {
			return stack.isEmpty() ? 0 : stack.lastKey() + 1;
		}
	}

	@Override
	public int getSuccessorFrameLevel(TargetObject successor) {
		for (TargetObject p = successor; p != null; p = p.getParent()) {
			if (p instanceof TargetStackFrame) {
				if (!PathUtils.isIndex(p.getPath())) {
					return 0;
				}
				int index = Integer.decode(p.getIndex());
				TargetStackFrame frame;
				synchronized (stack) {
					frame = stack.get(index);
				}
				if (!Objects.equals(p, frame)) {
					return 0;
				}
				return index;
			}
		}
		return 0;
	}

	protected boolean checkStackFrameRemoved(TargetObject invalid) {
		boolean removed;
		synchronized (stack) {
			removed = stack.values().remove(invalid);
		}
		if (removed) {
			popStack();
		}
		return removed;
	}

	public Address pcFromStack() {
		TargetStackFrame frame;
		synchronized (stack) {
			frame = stack.get(0);
		}
		if (frame == null) {
			return null;
		}
		return frame.getProgramCounter();
	}

	@Override
	public TraceStackFrame getTraceStackFrame(TraceThread thread, int level) {
		TraceStack latest = stackManager.getLatestStack(thread, recorder.getSnap());
		if (latest == null) {
			return null;
		}
		return latest.getFrame(level, false);
	}

	@Override
	public TargetStackFrame getTargetStackFrame(int frameLevel) {
		synchronized (stack) {
			return stack.get(frameLevel);
		}
	}

}
