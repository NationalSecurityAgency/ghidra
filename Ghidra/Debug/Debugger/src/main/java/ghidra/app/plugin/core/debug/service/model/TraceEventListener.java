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

import java.lang.invoke.MethodHandles;
import java.nio.ByteBuffer;
import java.util.*;

import ghidra.app.plugin.core.debug.service.model.interfaces.ManagedStackRecorder;
import ghidra.app.plugin.core.debug.service.model.interfaces.ManagedThreadRecorder;
import ghidra.dbg.*;
import ghidra.dbg.error.DebuggerMemoryAccessException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.util.DebuggerCallbackReorderer;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.modules.TraceModule;
import ghidra.util.Msg;
import ghidra.util.TimedMsg;
import ghidra.util.datastruct.PrivatelyQueuedListener;
import ghidra.util.exception.DuplicateNameException;

public class TraceEventListener extends AnnotatedDebuggerAttributeListener {

	private final DefaultTraceRecorder recorder;
	private final TargetObject target;
	private final Trace trace;
	private final TraceMemoryManager memoryManager;

	private boolean valid = true;
	protected final DebuggerCallbackReorderer reorderer = new DebuggerCallbackReorderer(this);
	protected final PrivatelyQueuedListener<DebuggerModelListener> queue;

	private boolean ignoreInvalidation = false;

	public TraceEventListener(TraceObjectManager collection) {
		super(MethodHandles.lookup());
		this.recorder = collection.getRecorder();

		this.queue = new PrivatelyQueuedListener<>(DebuggerModelListener.class,
			recorder.privateQueue, reorderer);

		this.target = recorder.getTarget();
		this.trace = recorder.getTrace();
		this.memoryManager = trace.getMemoryManager();
	}

	public void init() {
		DebuggerObjectModel model = target.getModel();
		model.addModelListener(queue.in, true);
	}

	private boolean successor(TargetObject ref) {
		return PathUtils.isAncestor(target.getPath(), ref.getPath());
	}

	private boolean anyRef(Collection<Object> parameters) {
		for (Object p : parameters) {
			if (!(p instanceof TargetObject)) {
				continue;
			}
			return true;
		}
		return false;
	}

	private boolean anySuccessor(Collection<Object> parameters) {
		for (Object p : parameters) {
			if (!(p instanceof TargetObject)) {
				continue;
			}
			TargetObject ref = (TargetObject) p;
			if (!successor(ref)) {
				continue;
			}
			return true;
		}
		return false;
	}

	private boolean eventApplies(TargetObject eventThread, TargetEventType type,
			List<Object> parameters) {
		if (eventThread != null) {
			return successor(eventThread);
		}
		if (anyRef(parameters)) {
			return anySuccessor(parameters);
		}
		return true; // Some session-wide event, I suppose
	}

	@Override
	public void event(TargetObject object, TargetThread eventThread, TargetEventType type,
			String description, List<Object> parameters) {
		if (!valid) {
			return;
		}
		TimedMsg.debug(this, "Event: " + type + " thread=" + eventThread + " description=" +
			description + " params=" + parameters);
		// Just use this to step the snaps. Creation/destruction still handled in add/remove
		if (eventThread == null) {
			if (!type.equals(TargetEventType.PROCESS_CREATED)) {
				Msg.error(this, "Null eventThread for " + type);
			}
			return;
		}
		if (!eventApplies(eventThread, type, parameters)) {
			return;
		}
		if (type == TargetEventType.RUNNING) {
			/**
			 * Do not permit the current snapshot to be invalidated on account of the target
			 * running. When the STOP occurs, a new (completely UNKNOWN) snapshot is generated.
			 */
			ignoreInvalidation = true;
			return;
			/**
			 * TODO: Perhaps some configuration for this later. It's kind of interesting to record
			 * the RUNNING event time, but it gets pedantic when these exist between steps.
			 */
		}
		ManagedThreadRecorder rec = recorder.getThreadRecorder(eventThread);
		recorder.createSnapshot(description, rec == null ? null : rec.getTraceThread(), null);
		ignoreInvalidation = false;

		if (type == TargetEventType.MODULE_LOADED) {
			long snap = recorder.getSnap();
			Object p0 = parameters.get(0);
			if (!(p0 instanceof TargetModule)) {
				return;
			}
			TargetModule mod = (TargetModule) p0;
			String modPath = mod.getJoinedPath(".");
			recorder.parTx.execute("Adjust module load: " + modPath, () -> {
				TraceModule traceModule = recorder.getTraceModule(mod);
				if (traceModule == null) {
					return;
				}
				try {
					traceModule.setLoadedSnap(snap);
				}
				catch (DuplicateNameException e) {
					Msg.error(this, "Could not set module loaded snap", e);
				}
			}, modPath);
		}
	}

	@AttributeCallback(TargetExecutionStateful.STATE_ATTRIBUTE_NAME)
	public void executionStateChanged(TargetObject stateful, TargetExecutionState state) {
		if (!valid) {
			return;
		}
		TimedMsg.debug(this, "State " + state + " for " + stateful);
		TargetObject x = recorder.objectManager.findThreadOrProcess(stateful);
		if (x != null) {
			if (x == target && state == TargetExecutionState.TERMINATED) {
				recorder.stopRecording();
				return;
			}
			ManagedThreadRecorder rec = null;
			if (x instanceof TargetThread) {
				rec = recorder.getThreadRecorder((TargetThread) x);
			}
			if (rec != null) {
				rec.stateChanged(state);
			}
			// Else we'll discover it and sync state later
		}
	}

	@Override
	public void invalidateCacheRequested(TargetObject object) {
		if (!valid) {
			return;
		}
		if (ignoreInvalidation) {
			return;
		}
		if (object instanceof TargetRegisterBank) {
			ManagedThreadRecorder rec = recorder.getThreadRecorderForSuccessor(object);
			if (rec != null) {
				rec.invalidateRegisterValues((TargetRegisterBank) object);
			}
		}
		if (object instanceof TargetMemory) {
			long snap = recorder.getSnap();
			String path = object.getJoinedPath(".");
			recorder.parTx.execute("Memory invalidated: " + path, () -> {
				AddressSet set = trace.getBaseLanguage().getAddressFactory().getAddressSet();
				memoryManager.setState(snap, set, TraceMemoryState.UNKNOWN);
			}, path);
		}
	}

	@Override
	public void registersUpdated(TargetObject bank, Map<String, byte[]> updates) {
		if (!valid) {
			return;
		}
		ManagedThreadRecorder rec = recorder.getThreadRecorderForSuccessor(bank);
		if (rec != null) {
			rec.recordRegisterValues((TargetRegisterBank) bank, updates);
		}
	}

	@Override
	public void memoryUpdated(TargetObject memory, Address address, byte[] data) {
		if (!valid) {
			return;
		}
		synchronized (recorder) {
			if (recorder.getMemoryMapper() == null) {
				Msg.warn(this, "Received memory write before a region has been added");
				return;
			}
		}
		Address traceAddr = recorder.getMemoryMapper().targetToTrace(address);
		long snap = recorder.getSnap();
		TimedMsg.debug(this, "Memory updated: " + address + " (" + data.length + ")");
		String path = memory.getJoinedPath(".");
		recorder.parTx.execute("Memory observed: " + path, () -> {
			memoryManager.putBytes(snap, traceAddr, ByteBuffer.wrap(data));
		}, path); // sel could be rand()...
	}

	@Override
	public void memoryReadError(TargetObject memory, AddressRange range,
			DebuggerMemoryAccessException e) {
		if (!valid) {
			return;
		}
		Msg.error(this, "Error reading range " + range, e);
		Address traceMin = recorder.getMemoryMapper().targetToTrace(range.getMinAddress());
		long snap = recorder.getSnap();
		String path = memory.getJoinedPath(".");
		recorder.parTx.execute("Memory read error: " + path, () -> {
			memoryManager.setState(snap, traceMin, TraceMemoryState.ERROR);
			// TODO: Bookmark to describe error?
		}, path); // sel could be rand()...
	}

	protected void stackUpdated(TargetStack stack) {
		ManagedStackRecorder rec = recorder.getThreadRecorderForSuccessor(stack).getStackRecorder();
		rec.recordStack();
	}

	@AttributeCallback(TargetFocusScope.FOCUS_ATTRIBUTE_NAME)
	public void focusChanged(TargetObject scope, TargetObject focused) {
		if (!valid) {
			return;
		}
		if (PathUtils.isAncestor(target.getPath(), focused.getPath())) {
			recorder.setCurrentFocus(focused);
		}
	}

	public RecorderThreadMap getThreadMap() {
		return recorder.getThreadMap();
	}

	public void dispose() {
		target.getModel().removeModelListener(reorderer);
		reorderer.dispose();
	}

}
