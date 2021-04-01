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
import java.util.concurrent.Executors;

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
	final PermanentTransactionExecutor tx;

	public DefaultStackRecorder(TraceThread thread, DefaultTraceRecorder recorder) {
		this.thread = thread;
		this.recorder = recorder;
		this.trace = recorder.getTrace();
		this.stackManager = trace.getStackManager();
		this.tx = new PermanentTransactionExecutor(trace,
			"ModuleRecorder:" + recorder.target.getJoinedPath("."),
			Executors::newSingleThreadExecutor, 100);
	}

	@Override
	public void offerStackFrame(TargetStackFrame frame) {
		recordFrame(frame);
	}

	@Override
	public void recordStack() {
		long snap = recorder.getSnap();
		tx.execute("Stack changed", () -> {
			TraceStack traceStack = stackManager.getStack(thread, snap, true);
			traceStack.setDepth(stackDepth(), false);
			for (Map.Entry<Integer, TargetStackFrame> ent : stack.entrySet()) {
				Address tracePc = recorder.getMemoryMapper()
						.targetToTrace(ent.getValue().getProgramCounter());
				doRecordFrame(traceStack, ent.getKey(), tracePc);
			}
		});
	}

	public void popStack() {
		long snap = recorder.getSnap();
		tx.execute("Stack popped", () -> {
			TraceStack traceStack = stackManager.getStack(thread, snap, true);
			traceStack.setDepth(stackDepth(), false);
		});
	}

	public void doRecordFrame(TraceStack traceStack, int frameLevel, Address pc) {
		TraceStackFrame traceFrame = traceStack.getFrame(frameLevel, true);
		traceFrame.setProgramCounter(pc);
	}

	public void recordFrame(TargetStackFrame frame) {
		tx.execute("Stack frame added", () -> {
			stack.put(getFrameLevel(frame), frame);
			DebuggerMemoryMapper memoryMapper = recorder.getMemoryMapper();
			if (memoryMapper == null) {
				return;
			}
			Address pc = frame.getProgramCounter();
			Address tracePc = pc == null ? null : memoryMapper.targetToTrace(pc);
			TraceStack traceStack = stackManager.getStack(thread, recorder.getSnap(), true);
			doRecordFrame(traceStack, getFrameLevel(frame), tracePc);
		});
	}

	protected int stackDepth() {
		return stack.isEmpty() ? 0 : stack.lastKey() + 1;
	}

	@Override
	public int getSuccessorFrameLevel(TargetObject successor) {
		NavigableSet<Integer> observedPathLengths = new TreeSet<>();
		for (TargetStackFrame frame : stack.values()) {
			observedPathLengths.add(frame.getPath().size());
		}
		List<String> path = successor.getPath();
		for (int l : observedPathLengths.descendingSet()) {
			if (l > path.size()) {
				continue;
			}
			List<String> sub = path.subList(0, l);
			if (!PathUtils.isIndex(sub)) {
				continue;
			}
			int index = Integer.decode(PathUtils.getIndex(sub));
			TargetStackFrame frame = stack.get(index);
			if (frame == null || !Objects.equals(sub, frame.getPath())) {
				continue;
			}
			return index;
		}
		return 0;
	}

	protected boolean checkStackFrameRemoved(TargetObject invalid) {
		if (stack.values().remove(invalid)) {
			popStack();
			return true;
		}
		return false;
	}

	public Address pcFromStack() {
		TargetStackFrame frame = stack.get(0);
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
		return stack.get(frameLevel);
	}

}
