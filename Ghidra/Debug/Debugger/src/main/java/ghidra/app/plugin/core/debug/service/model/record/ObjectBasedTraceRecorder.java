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
package ghidra.app.plugin.core.debug.service.model.record;

import java.lang.invoke.MethodHandles;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import com.google.common.collect.Range;

import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.app.plugin.core.debug.service.model.DebuggerModelServicePlugin;
import ghidra.app.plugin.core.debug.service.model.PermanentTransactionExecutor;
import ghidra.app.services.TraceRecorder;
import ghidra.app.services.TraceRecorderListener;
import ghidra.async.AsyncUtils;
import ghidra.dbg.AnnotatedDebuggerAttributeListener;
import ghidra.dbg.error.DebuggerMemoryAccessException;
import ghidra.dbg.error.DebuggerModelAccessException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.database.module.TraceObjectSection;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.memory.TraceObjectMemoryRegion;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.stack.TraceObjectStackFrame;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.Msg;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.task.TaskMonitor;

public class ObjectBasedTraceRecorder implements TraceRecorder {
	protected static final int POOL_SIZE = Math.min(16, Runtime.getRuntime().availableProcessors());
	protected static final int DELAY_MS = 100;
	protected static final int BLOCK_BITS = 12;

	protected final Trace trace;
	protected final TargetObject target;
	protected final ObjectBasedDebuggerTargetTraceMapper mapper;
	protected final DebuggerMemoryMapper memoryMapper;
	protected final DebuggerRegisterMapper emptyRegisterMapper = new EmptyDebuggerRegisterMapper();

	protected final TimeRecorder timeRecorder;
	protected final ObjectRecorder objectRecorder;
	protected final MemoryRecorder memoryRecorder;
	protected final DataTypeRecorder dataTypeRecorder;
	protected final SymbolRecorder symbolRecorder;

	// upstream listeners
	protected final ListenerForRecord listenerForRecord;

	protected final ListenerSet<TraceRecorderListener> listeners =
		new ListenerSet<>(TraceRecorderListener.class);

	// TODO: I don't like this here. Should ask the model, not the recorder.
	protected TargetObject curFocus;
	protected boolean valid = true;

	protected class ListenerForRecord extends AnnotatedDebuggerAttributeListener {
		private final PermanentTransactionExecutor tx =
			new PermanentTransactionExecutor(trace, "OBTraceRecorder: ", POOL_SIZE, DELAY_MS);

		private boolean ignoreInvalidation = false;

		// TODO: Do I need DebuggerCallbackReorderer?
		public ListenerForRecord() {
			super(MethodHandles.lookup());
		}

		@Override
		public void event(TargetObject object, TargetThread eventThread, TargetEventType type,
				String description, List<Object> parameters) {
			if (!valid) {
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
				 * TODO: Perhaps some configuration for this later. It's kind of interesting to
				 * record the RUNNING event time, but it gets pedantic when these exist between
				 * steps.
				 */
			}
			/**
			 * Snapshot creation should not be offloaded to parallel executor or we may confuse
			 * event snaps.
			 */
			TraceObjectThread traceEventThread =
				objectRecorder.getTraceInterface(eventThread, TraceObjectThread.class);
			timeRecorder.createSnapshot(description, traceEventThread, null);
			ignoreInvalidation = false;
			// NB. Need not worry about CREATED, LOADED, etc. Just recording objects.
		}

		// NB. ignore executionStateChanged, since recording whole model

		@Override
		public void invalidateCacheRequested(TargetObject object) {
			if (!valid) {
				return;
			}
			if (ignoreInvalidation) {
				return;
			}
			if (object instanceof TargetMemory) {
				long snap = timeRecorder.getSnap();
				String path = object.getJoinedPath(".");
				tx.execute("Memory invalidated: " + path, () -> {
					memoryRecorder.invalidate((TargetMemory) object, snap);
				}, path);
			}
		}

		// NB. ignore registersUpdated. All object-based, now.

		@Override
		public void memoryUpdated(TargetObject memory, Address address, byte[] data) {
			if (!valid) {
				return;
			}
			long snap = timeRecorder.getSnap();
			String path = memory.getJoinedPath(".");
			Address tAddress = getMemoryMapper().targetToTrace(address);
			tx.execute("Memory observed: " + path, () -> {
				memoryRecorder.recordMemory(snap, tAddress, data);
			}, path);
		}

		@Override
		public void memoryReadError(TargetObject memory, AddressRange range,
				DebuggerMemoryAccessException e) {
			if (!valid) {
				return;
			}
			long snap = timeRecorder.getSnap();
			String path = memory.getJoinedPath(".");
			Address tMin = getMemoryMapper().targetToTrace(range.getMinAddress());
			tx.execute("Memory read error: " + path, () -> {
				memoryRecorder.recordError(snap, tMin, e);
			}, path);
		}

		@AttributeCallback(TargetFocusScope.FOCUS_ATTRIBUTE_NAME)
		protected void focusChanged(TargetObject scope, TargetObject focused) {
			if (!valid) {
				return;
			}
			// NB. Don't care about ancestry. Focus should be model-wide anyway.
			curFocus = focused;
		}

		@Override
		public void created(TargetObject object) {
			if (!valid) {
				return;
			}
			long snap = timeRecorder.getSnap();
			String path = object.getJoinedPath(".");
			// Don't offload, because we need a consistent map
			try (UndoableTransaction tid =
				UndoableTransaction.start(trace, "Object created: " + path)) {
				objectRecorder.recordCreated(snap, object);
			}
		}

		@Override
		public void invalidated(TargetObject object, TargetObject branch, String reason) {
			if (!valid) {
				return;
			}
			long snap = timeRecorder.getSnap();
			String path = object.getJoinedPath(".");
			tx.execute("Object invalidated: " + path, () -> {
				objectRecorder.recordInvalidated(snap, object);
			}, path);
			if (object == target) {
				stopRecording();
				return;
			}
			if (object instanceof TargetMemory) {
				memoryRecorder.removeMemory((TargetMemory) object);
			}
			if (object instanceof TargetMemoryRegion) {
				memoryRecorder.removeRegion((TargetMemoryRegion) object);
			}
		}

		@Override
		public void attributesChanged(TargetObject object, Collection<String> removed,
				Map<String, ?> added) {
			if (!valid) {
				return;
			}
			long snap = timeRecorder.getSnap();
			String path = object.getJoinedPath(".");
			tx.execute("Object attributes changed: " + path, () -> {
				objectRecorder.recordAttributes(snap, object, removed, added);
			}, path);
			super.attributesChanged(object, removed, added);
		}

		@AttributeCallback(TargetMemoryRegion.RANGE_ATTRIBUTE_NAME)
		public void rangeChanged(TargetObject object, AddressRange range) {
			if (!valid) {
				return;
			}
			if (!(object instanceof TargetMemoryRegion)) {
				return;
			}
			memoryRecorder.adjustRegionRange((TargetMemoryRegion) object, range);
		}

		@AttributeCallback(TargetMemoryRegion.MEMORY_ATTRIBUTE_NAME)
		public void memoryChanged(TargetObject object, TargetMemory memory) {
			if (!valid) {
				return;
			}
			if (!(object instanceof TargetMemoryRegion)) {
				return;
			}
			memoryRecorder.addRegionMemory((TargetMemoryRegion) object, memory);
		}

		@Override
		public void elementsChanged(TargetObject object, Collection<String> removed,
				Map<String, ? extends TargetObject> added) {
			if (!valid) {
				return;
			}
			long snap = timeRecorder.getSnap();
			String path = object.getJoinedPath(".");
			tx.execute("Object elements changed: " + path, () -> {
				objectRecorder.recordElements(snap, object, removed, added);
			}, path);
		}
	}

	public ObjectBasedTraceRecorder(DebuggerModelServicePlugin service, Trace trace,
			TargetObject target, ObjectBasedDebuggerTargetTraceMapper mapper) {
		trace.addConsumer(this);
		this.trace = trace;
		this.target = target;
		this.mapper = mapper;

		// TODO: Don't depend on memory in interface.
		// TODO: offerMemory not async
		memoryMapper = mapper.offerMemory(null).getNow(null);

		timeRecorder = new TimeRecorder(this);
		objectRecorder = new ObjectRecorder(this);
		memoryRecorder = new MemoryRecorder(this);
		dataTypeRecorder = new DataTypeRecorder(this);
		symbolRecorder = new SymbolRecorder(this);

		listenerForRecord = new ListenerForRecord();
	}

	@Override
	public CompletableFuture<Void> init() {
		// TODO: Make this method synchronous?
		timeRecorder.createSnapshot("Started recording " + target.getModel(), null, null);
		target.getModel().addModelListener(listenerForRecord, true);
		return AsyncUtils.NIL;
	}

	@Override
	public TargetObject getTarget() {
		return target;
	}

	@Override
	public Trace getTrace() {
		return trace;
	}

	@Override
	public long getSnap() {
		return timeRecorder.getSnap();
	}

	@Override
	public TraceSnapshot forceSnapshot() {
		return timeRecorder.forceSnapshot();
	}

	@Override
	public boolean isRecording() {
		return valid;
	}

	@Override
	public void stopRecording() {
		invalidate();
		fireRecordingStopped();
	}

	protected void invalidate() {
		target.getModel().removeModelListener(listenerForRecord);
		synchronized (this) {
			if (!valid) {
				return;
			}
			valid = false;
		}
		trace.release(this);
	}

	@Override
	public void addListener(TraceRecorderListener listener) {
		listeners.add(listener);
	}

	@Override
	public void removeListener(TraceRecorderListener listener) {
		listeners.remove(listener);
	}

	@Override
	public TargetBreakpointLocation getTargetBreakpoint(TraceBreakpoint bpt) {
		return objectRecorder.getTargetInterface(bpt, TraceObjectBreakpointLocation.class,
			TargetBreakpointLocation.class);
	}

	@Override
	public TraceBreakpoint getTraceBreakpoint(TargetBreakpointLocation bpt) {
		return objectRecorder.getTraceInterface(bpt, TraceObjectBreakpointLocation.class);
	}

	@Override
	public TargetMemoryRegion getTargetMemoryRegion(TraceMemoryRegion region) {
		return objectRecorder.getTargetInterface(region, TraceObjectMemoryRegion.class,
			TargetMemoryRegion.class);
	}

	@Override
	public TraceMemoryRegion getTraceMemoryRegion(TargetMemoryRegion region) {
		return objectRecorder.getTraceInterface(region, TraceObjectMemoryRegion.class);
	}

	@Override
	public TargetModule getTargetModule(TraceModule module) {
		return objectRecorder.getTargetInterface(module, TraceObjectModule.class,
			TargetModule.class);
	}

	@Override
	public TraceModule getTraceModule(TargetModule module) {
		return objectRecorder.getTraceInterface(module, TraceObjectModule.class);
	}

	@Override
	public TargetSection getTargetSection(TraceSection section) {
		return objectRecorder.getTargetInterface(section, TraceObjectSection.class,
			TargetSection.class);
	}

	@Override
	public TraceSection getTraceSection(TargetSection section) {
		return objectRecorder.getTraceInterface(section, TraceObjectSection.class);
	}

	@Override
	public TargetThread getTargetThread(TraceThread thread) {
		if (thread == null) {
			return null;
		}
		return objectRecorder.getTargetInterface(thread, TraceObjectThread.class,
			TargetThread.class);
	}

	@Override
	public TargetExecutionState getTargetThreadState(TargetThread thread) {
		return thread.getTypedAttributeNowByName(TargetExecutionStateful.STATE_ATTRIBUTE_NAME,
			TargetExecutionState.class, TargetExecutionState.INACTIVE);
	}

	@Override
	public TargetExecutionState getTargetThreadState(TraceThread thread) {
		return getTargetThreadState(getTargetThread(thread));
	}

	@Override
	public TargetRegisterBank getTargetRegisterBank(TraceThread thread, int frameLevel) {
		return objectRecorder.getTargetFrameInterface(thread, frameLevel, TargetRegisterBank.class);
	}

	@Override
	public TraceThread getTraceThread(TargetThread thread) {
		return objectRecorder.getTraceInterface(thread, TraceObjectThread.class);
	}

	@Override
	public TraceThread getTraceThreadForSuccessor(TargetObject successor) {
		TraceObject traceObject = objectRecorder.toTrace(successor);
		if (traceObject == null) {
			return null;
		}
		return traceObject.queryCanonicalAncestorsInterface(
			TraceObjectThread.class).findFirst().orElse(null);
	}

	@Override
	public TraceStackFrame getTraceStackFrame(TargetStackFrame frame) {
		return objectRecorder.getTraceInterface(frame, TraceObjectStackFrame.class);
	}

	@Override
	public TraceStackFrame getTraceStackFrameForSuccessor(TargetObject successor) {
		TraceObject traceObject = objectRecorder.toTrace(successor);
		if (traceObject == null) {
			return null;
		}
		return traceObject.queryCanonicalAncestorsInterface(
			TraceObjectStackFrame.class).findFirst().orElse(null);
	}

	@Override
	public TargetStackFrame getTargetStackFrame(TraceThread thread, int frameLevel) {
		return objectRecorder.getTargetFrameInterface(thread, frameLevel, TargetStackFrame.class);
	}

	@Override
	public Set<TargetThread> getLiveTargetThreads() {
		return trace.getObjectManager()
				.getRootObject()
				.querySuccessorsInterface(Range.singleton(getSnap()), TraceObjectThread.class)
				.map(t -> objectRecorder.getTargetInterface(t.getObject(), TargetThread.class))
				.collect(Collectors.toSet());
	}

	@Override
	public DebuggerRegisterMapper getRegisterMapper(TraceThread thread) {
		return emptyRegisterMapper;
	}

	@Override
	public DebuggerMemoryMapper getMemoryMapper() {
		return memoryMapper;
	}

	@Override
	public boolean isRegisterBankAccessible(TargetRegisterBank bank) {
		// TODO: This seems a little aggressive, but the accessbility thing is already out of hand
		return true;
	}

	@Override
	public boolean isRegisterBankAccessible(TraceThread thread, int frameLevel) {
		// TODO: This seems a little aggressive, but the accessbility thing is already out of hand
		return true;
	}

	@Override
	public AddressSetView getAccessibleMemory() {
		return memoryRecorder.getAccessible();
	}

	@Override
	public CompletableFuture<Map<Register, RegisterValue>> captureThreadRegisters(
			TraceThread thread, int frameLevel, Set<Register> registers) {
		return CompletableFuture.completedFuture(Map.of());
	}

	@Override
	public CompletableFuture<Void> writeThreadRegisters(TraceThread thread, int frameLevel,
			Map<Register, RegisterValue> values) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CompletableFuture<byte[]> readMemory(Address start, int length) {
		return memoryRecorder.read(start, length);
	}

	@Override
	public CompletableFuture<Void> writeMemory(Address start, byte[] data) {
		return memoryRecorder.write(start, data);
	}

	@Override
	public CompletableFuture<NavigableMap<Address, byte[]>> readMemoryBlocks(
			AddressSetView set, TaskMonitor monitor, boolean returnResult) {
		return RecorderUtils.INSTANCE.readMemoryBlocks(this, BLOCK_BITS, set, monitor,
			returnResult);
	}

	@Override
	public CompletableFuture<Void> captureDataTypes(TraceModule module, TaskMonitor monitor) {
		return dataTypeRecorder.captureDataTypes(getTargetModule(module), monitor);
	}

	@Override
	public CompletableFuture<Void> captureDataTypes(TargetDataTypeNamespace namespace,
			TaskMonitor monitor) {
		return dataTypeRecorder.captureDataTypes(namespace, monitor);
	}

	@Override
	public CompletableFuture<Void> captureSymbols(TraceModule module, TaskMonitor monitor) {
		return symbolRecorder.captureSymbols(getTargetModule(module), monitor);
	}

	@Override
	public CompletableFuture<Void> captureSymbols(TargetSymbolNamespace namespace,
			TaskMonitor monitor) {
		return symbolRecorder.captureSymbols(namespace, monitor);
	}

	@Override
	public List<TargetBreakpointSpecContainer> collectBreakpointContainers(TargetThread thread) {
		if (thread == null) {
			return objectRecorder.collectTargetSuccessors(target,
				TargetBreakpointSpecContainer.class);
		}
		return objectRecorder.collectTargetSuccessors(thread, TargetBreakpointSpecContainer.class);
	}

	private class BreakpointConvention {
		private final TraceObjectThread thread;
		private final TraceObject process;

		private BreakpointConvention(TraceObjectThread thread) {
			this.thread = thread;
			TraceObject object = thread.getObject();
			this.process = object
					.queryAncestorsTargetInterface(Range.singleton(getSnap()), TargetProcess.class)
					.map(p -> p.getSource(object))
					.findFirst()
					.orElse(null);
		}

		private boolean appliesTo(TraceObjectBreakpointLocation loc) {
			TraceObject object = loc.getObject();
			if (object.queryAncestorsInterface(Range.singleton(getSnap()), TraceObjectThread.class)
					.anyMatch(t -> t == thread)) {
				return true;
			}
			if (process == null) {
				return false;
			}
			return object
					.queryAncestorsTargetInterface(Range.singleton(getSnap()), TargetProcess.class)
					.map(p -> p.getSource(object))
					.anyMatch(p -> p == process);
		}
	}

	@Override
	public List<TargetBreakpointLocation> collectBreakpoints(TargetThread thread) {
		if (thread == null) {
			return objectRecorder.collectTargetSuccessors(target, TargetBreakpointLocation.class);
		}
		BreakpointConvention convention = new BreakpointConvention(
			objectRecorder.getTraceInterface(thread, TraceObjectThread.class));
		return trace.getObjectManager()
				.queryAllInterface(Range.singleton(getSnap()), TraceObjectBreakpointLocation.class)
				.filter(convention::appliesTo)
				.map(tl -> objectRecorder.getTargetInterface(tl.getObject(),
					TargetBreakpointLocation.class))
				.collect(Collectors.toList());
	}

	@Override
	public Set<TraceBreakpointKind> getSupportedBreakpointKinds() {
		return objectRecorder.collectTargetSuccessors(target, TargetBreakpointSpecContainer.class)
				.stream()
				.flatMap(c -> c.getSupportedBreakpointKinds().stream())
				.map(k -> TraceRecorder.targetToTraceBreakpointKind(k))
				.collect(Collectors.toSet());
	}

	@Override
	public boolean isSupportsFocus() {
		return objectRecorder.isSupportsFocus;
	}

	@Override
	public TargetObject getFocus() {
		return curFocus;
	}

	@Override
	public CompletableFuture<Boolean> requestFocus(TargetObject focus) {
		for (TargetFocusScope scope : objectRecorder.collectTargetSuccessors(target,
			TargetFocusScope.class)) {
			if (PathUtils.isAncestor(scope.getPath(), focus.getPath())) {
				return scope.requestFocus(focus).thenApply(__ -> true).exceptionally(ex -> {
					ex = AsyncUtils.unwrapThrowable(ex);
					String msg = "Could not focus " + focus + ": " + ex.getMessage();
					if (ex instanceof DebuggerModelAccessException) {
						Msg.info(this, msg);
					}
					else {
						Msg.error(this, msg, ex);
					}
					return false;
				});
			}
		}
		Msg.info(this, "Could not find suitable focus scope for " + focus);
		return CompletableFuture.completedFuture(false);
	}

	// UNUSED?
	@Override
	public CompletableFuture<Void> flushTransactions() {
		return listenerForRecord.tx.flush();
	}

	protected void fireSnapAdvanced(long key) {
		listeners.fire.snapAdvanced(this, key);
	}

	protected void fireRecordingStopped() {
		listeners.fire.recordingStopped(this);
	}

	// TODO: Deprecate/remove the other callbacks: registerBankMapped, *accessibilityChanged
}
