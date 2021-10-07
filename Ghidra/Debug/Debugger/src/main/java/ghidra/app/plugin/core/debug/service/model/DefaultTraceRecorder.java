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
import java.util.concurrent.*;

import org.apache.commons.lang3.concurrent.BasicThreadFactory;

import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.app.plugin.core.debug.service.model.interfaces.*;
import ghidra.app.services.TraceRecorder;
import ghidra.app.services.TraceRecorderListener;
import ghidra.async.AsyncLazyValue;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.error.DebuggerModelAccessException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.util.PathUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceSection;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.Msg;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class DefaultTraceRecorder implements TraceRecorder {
	static final int POOL_SIZE = Math.min(16, Runtime.getRuntime().availableProcessors());

	protected final DebuggerModelServicePlugin plugin;
	protected final PluginTool tool;
	protected final TargetObject target;
	protected final Trace trace;

	final RecorderThreadMap threadMap = new RecorderThreadMap();

	TraceObjectManager objectManager;

	DefaultBreakpointRecorder breakpointRecorder;
	DefaultDataTypeRecorder datatypeRecorder;
	DefaultMemoryRecorder memoryRecorder;
	DefaultModuleRecorder moduleRecorder;
	DefaultProcessRecorder processRecorder;
	DefaultSymbolRecorder symbolRecorder;
	DefaultTimeRecorder timeRecorder;

	//protected final PermanentTransactionExecutor seqTx;
	protected final PermanentTransactionExecutor parTx;
	protected final Executor privateQueue = Executors.newSingleThreadExecutor(
		new BasicThreadFactory.Builder().namingPattern("DTR-EventQueue-%d").build());

	protected final AsyncLazyValue<Void> lazyInit = new AsyncLazyValue<>(this::doInit);
	private boolean valid = true;

	public DefaultTraceRecorder(DebuggerModelServicePlugin plugin, Trace trace, TargetObject target,
			DefaultDebuggerTargetTraceMapper mapper) {
		this.plugin = plugin;
		this.tool = plugin.getTool();
		this.trace = trace;
		this.target = target;

		//seqTx = new PermanentTransactionExecutor(
		//	trace, "TraceRecorder(seq): " + target.getJoinedPath("."), 1, 100);
		parTx = new PermanentTransactionExecutor(
			trace, "TraceRecorder(par): " + target.getJoinedPath("."), POOL_SIZE, 100);

		this.processRecorder = new DefaultProcessRecorder(this);
		this.breakpointRecorder = new DefaultBreakpointRecorder(this);
		this.datatypeRecorder = new DefaultDataTypeRecorder(this);
		this.memoryRecorder = new DefaultMemoryRecorder(this);
		this.moduleRecorder = new DefaultModuleRecorder(this);
		this.symbolRecorder = new DefaultSymbolRecorder(this);
		this.timeRecorder = new DefaultTimeRecorder(this);
		this.objectManager = new TraceObjectManager(target, mapper, this);

		trace.addConsumer(this);

	}

	/*---------------- OBJECT MANAGER METHODS -------------------*/

	@Override
	public TargetBreakpointLocation getTargetBreakpoint(TraceBreakpoint bpt) {
		return objectManager.getTargetBreakpoint(bpt);
	}

	@Override
	public TargetMemoryRegion getTargetMemoryRegion(TraceMemoryRegion region) {
		return objectManager.getTargetMemoryRegion(region);
	}

	@Override
	public TargetModule getTargetModule(TraceModule module) {
		return objectManager.getTargetModule(module);
	}

	@Override
	public TargetSection getTargetSection(TraceSection section) {
		return objectManager.getTargetSection(section);
	}

	@Override
	public List<TargetBreakpointSpecContainer> collectBreakpointContainers(TargetThread thread) {
		List<TargetBreakpointSpecContainer> result = new ArrayList<>();
		objectManager.onBreakpointContainers(thread, result::add);
		return result;
	}

	@Override
	public List<TargetBreakpointLocation> collectBreakpoints(TargetThread thread) {
		return objectManager.collectBreakpoints(thread);
	}

	@Override
	public Set<TraceBreakpointKind> getSupportedBreakpointKinds() {
		Set<TargetBreakpointKind> tKinds = new HashSet<>();
		objectManager.onBreakpointContainers(null, cont -> {
			tKinds.addAll(cont.getSupportedBreakpointKinds());
		});
		return TraceRecorder.targetToTraceBreakpointKinds(tKinds);

	}
	/*---------------- RECORDER ACCESS METHODS -------------------*/

	@Override
	public TraceBreakpoint getTraceBreakpoint(TargetBreakpointLocation bpt) {
		return breakpointRecorder.getTraceBreakpoint(bpt);
	}

	@Override
	public TraceMemoryRegion getTraceMemoryRegion(TargetMemoryRegion region) {
		return memoryRecorder.getTraceMemoryRegion(region);
	}

	@Override
	public TraceModule getTraceModule(TargetModule module) {
		return moduleRecorder.getTraceModule(module);
	}

	@Override
	public TraceSection getTraceSection(TargetSection section) {
		return moduleRecorder.getTraceSection(section);
	}

	/*---------------- BY-THREAD OBJECT MANAGER METHODS -------------------*/

	public ManagedThreadRecorder computeIfAbsent(TargetThread thread) {
		AbstractDebuggerObjectModel model = (AbstractDebuggerObjectModel) thread.getModel();
		synchronized (model.lock) {
			if (!threadMap.byTargetThread.containsKey(thread)) {
				if (objectManager.hasObject(thread)) {
					createTraceThread(thread);
				}
			}
			return threadMap.get(thread);
		}
	}

	public TraceThread createTraceThread(TargetThread thread) {
		//System.err.println("createTraceThread " + thread);
		String path = PathUtils.toString(thread.getPath());
		// NB. Keep this on service thread, since thread creation must precede any dependent
		try (RecorderPermanentTransaction tid =
			RecorderPermanentTransaction.start(trace, path + " created")) {
			// Note, if THREAD_CREATED is emitted, it will adjust the creation snap
			TraceThread tthread =
				trace.getThreadManager().createThread(path, thread.getShortDisplay(), getSnap());
			threadMap.put(
				new DefaultThreadRecorder(this, objectManager.getMapper(), thread, tthread));
			return tthread;
		}
		catch (DuplicateNameException e) {
			throw new AssertionError(e); // Should be a new thread in model
		}
	}

	@Override
	public TargetThread getTargetThread(TraceThread thread) {
		DefaultThreadRecorder rec = getThreadRecorder(thread);
		return rec == null ? null : rec.getTargetThread();
	}

	@Override
	public TargetExecutionState getTargetThreadState(TargetThread thread) {
		DefaultThreadRecorder rec = (DefaultThreadRecorder) getThreadRecorder(thread);
		return rec == null ? null : rec.state;
	}

	@Override
	public TargetExecutionState getTargetThreadState(TraceThread thread) {
		DefaultThreadRecorder rec = getThreadRecorder(thread);
		return rec == null ? null : rec.state;
	}

	@Override
	public TargetRegisterBank getTargetRegisterBank(TraceThread thread, int frameLevel) {
		DefaultThreadRecorder rec = getThreadRecorder(thread);
		return rec.getTargetRegisterBank(thread, frameLevel);
	}

	@Override
	public TargetStackFrame getTargetStackFrame(TraceThread thread, int frameLevel) {
		DefaultThreadRecorder rec = getThreadRecorder(thread);
		if (rec == null) {
			return null;
		}
		return rec.getStackRecorder().getTargetStackFrame(frameLevel);
	}

	/*---------------- BY-THREAD RECORDER ACCESS METHODS -------------------*/

	@Override
	public TraceThread getTraceThread(TargetThread thread) {
		ManagedThreadRecorder rec = getThreadRecorder(thread);
		return rec == null ? null : rec.getTraceThread();
	}

	@Override
	public TraceThread getTraceThreadForSuccessor(TargetObject successor) {
		ManagedThreadRecorder rec = getThreadRecorderForSuccessor(successor);
		return rec == null ? null : rec.getTraceThread();
	}

	@Override
	public TraceStackFrame getTraceStackFrame(TargetStackFrame frame) {
		// Not the most efficient, but only used in testing.
		return getTraceStackFrameForSuccessor(frame);
	}

	@Override
	public TraceStackFrame getTraceStackFrameForSuccessor(TargetObject successor) {
		ManagedThreadRecorder rec = getThreadRecorderForSuccessor(successor);
		if (rec == null) {
			return null;
		}
		ManagedStackRecorder stackRecorder = rec.getStackRecorder();
		int level = stackRecorder.getSuccessorFrameLevel(successor);
		return stackRecorder.getTraceStackFrame(rec.getTraceThread(), level);
	}

	/*---------------- CAPTURE METHODS -------------------*/

	@Override
	public CompletableFuture<NavigableMap<Address, byte[]>> captureProcessMemory(AddressSetView set,
			TaskMonitor monitor, boolean toMap) {
		if (set.isEmpty()) {
			return CompletableFuture.completedFuture(new TreeMap<>());
		}
		return memoryRecorder.captureProcessMemory(set, monitor, toMap);
	}

	@Override
	public CompletableFuture<Void> captureDataTypes(TargetDataTypeNamespace namespace,
			TaskMonitor monitor) {
		if (!valid) {
			return AsyncUtils.NIL;
		}
		return datatypeRecorder.captureDataTypes(namespace, monitor);
	}

	@Override
	public CompletableFuture<Void> captureDataTypes(TraceModule module, TaskMonitor monitor) {
		TargetModule targetModule = getTargetModule(module);
		if (targetModule == null) {
			Msg.error(this, "Module " + module + " is not loaded");
			return AsyncUtils.NIL;
		}
		return datatypeRecorder.captureDataTypes(targetModule, monitor);
	}

	@Override
	public CompletableFuture<Void> captureSymbols(TargetSymbolNamespace namespace,
			TaskMonitor monitor) {
		if (!valid) {
			return AsyncUtils.NIL;
		}
		return symbolRecorder.captureSymbols(namespace, monitor);
	}

	@Override
	public CompletableFuture<Void> captureSymbols(TraceModule module, TaskMonitor monitor) {
		TargetModule targetModule = getTargetModule(module);
		if (targetModule == null) {
			Msg.error(this, "Module " + module + " is not loaded");
			return AsyncUtils.NIL;
		}
		return symbolRecorder.captureSymbols(targetModule, monitor);
	}

	@Override
	public CompletableFuture<Map<Register, RegisterValue>> captureThreadRegisters(
			TraceThread thread, int frameLevel,
			Set<Register> registers) {
		DefaultThreadRecorder rec = getThreadRecorder(thread);
		return rec.captureThreadRegisters(thread, frameLevel, registers);
	}

	/*---------------- SNAPSHOT METHODS -------------------*/

	@Override
	public CompletableFuture<Void> init() {
		return lazyInit.request();
	}

	protected CompletableFuture<Void> doInit() {
		timeRecorder.createSnapshot(
			"Started recording" + PathUtils.toString(target.getPath()) + " in " + target.getModel(),
			null, null);
		objectManager.init();
		return AsyncUtils.NIL;

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
		getListeners().fire.recordingStopped(this);
	}

	protected void invalidate() {
		valid = false;
		objectManager.disposeModelListeners();
		trace.release(this);
	}

	/*---------------- FOCUS-SUPPORT METHODS -------------------*/

	protected TargetObject curFocus;

	@Override
	public boolean isSupportsFocus() {
		return findFocusScope() != null;
	}

	// NOTE: This may require the scope to be an ancestor of the target
	// That should be fine
	protected TargetFocusScope findFocusScope() {
		List<String> path = target.getModel()
				.getRootSchema()
				.searchForSuitable(TargetFocusScope.class, target.getPath());
		return (TargetFocusScope) target.getModel().getModelObject(path);
	}

	@Override
	public TargetObject getFocus() {
		if (curFocus == null) {
			TargetFocusScope focusScope = findFocusScope();
			if (focusScope == null) {
				return null;
			}
			TargetObject focus = focusScope.getFocus();
			if (focus == null || !PathUtils.isAncestor(getTarget().getPath(), focus.getPath())) {
				return null;
			}
			curFocus = focus;
		}
		return curFocus;
	}

	public void setCurrentFocus(TargetObject focused) {
		curFocus = focused;
	}

	@Override
	public CompletableFuture<Boolean> requestFocus(TargetObject focus) {
		if (!isSupportsFocus()) {
			return CompletableFuture
					.failedFuture(new IllegalArgumentException("Target does not support focus"));
		}
		if (!PathUtils.isAncestor(getTarget().getPath(), focus.getPath())) {
			return CompletableFuture.failedFuture(new IllegalArgumentException(
				"Requested focus path is not a successor of the target"));
		}
		TargetFocusScope focusScope = findFocusScope();
		if (!PathUtils.isAncestor(focusScope.getPath(), focus.getPath())) {
			// This should be rare, if not forbidden
			return CompletableFuture.failedFuture(new IllegalArgumentException(
				"Requested focus path is not a successor of the focus scope"));
		}
		return focusScope.requestFocus(focus).thenApply(__ -> true).exceptionally(ex -> {
			ex = AsyncUtils.unwrapThrowable(ex);
			if (ex instanceof DebuggerModelAccessException) {
				String msg = "Could not focus " + focus + ": " + ex.getMessage();
				Msg.info(this, msg);
				plugin.getTool().setStatusInfo(msg);
			}
			Msg.showError(this, null, "Focus Sync", "Could not focus " + focus, ex);
			return false;
		});
	}

	/*---------------- ACCESSOR METHODS -------------------*/

	@Override
	public TargetObject getTarget() {
		return target;
	}

	@Override
	public Trace getTrace() {
		return trace;
	}

	public RecorderThreadMap getThreadMap() {
		return threadMap;
	}

	public Set<TargetThread> getThreadsView() {
		return getThreadMap().byTargetThread.keySet();
	}

	// UNUSED?
	@Override
	public Set<TargetThread> getLiveTargetThreads() {
		return getThreadsView();
	}

	public DefaultThreadRecorder getThreadRecorder(TraceThread thread) {
		return (DefaultThreadRecorder) getThreadMap().get(thread);
	}

	public ManagedThreadRecorder getThreadRecorder(TargetThread thread) {
		return computeIfAbsent(thread);
	}

	public ManagedThreadRecorder getThreadRecorderForSuccessor(TargetObject successor) {
		TargetObject obj = successor;
		while (obj != null && !(obj instanceof TargetThread)) {
			obj = obj.getParent();
		}
		if (obj == null) {
			return null;
		}
		return computeIfAbsent((TargetThread) obj);
	}

	@Override
	public DebuggerMemoryMapper getMemoryMapper() {
		return objectManager.getMemoryMapper();
	}

	@Override
	public DebuggerRegisterMapper getRegisterMapper(TraceThread thread) {
		DefaultThreadRecorder rec = getThreadRecorder(thread);
		if (rec == null) {
			return null;
		}
		return rec.getRegisterMapper();
	}

	//public AbstractRecorderRegisterSet getThreadRegisters() {
	//	return objectManager.getThreadRegisters();
	//}

	/*---------------- LISTENER METHODS -------------------*/

	// UNUSED?
	@Override
	public TraceEventListener getListenerForRecord() {
		return objectManager.getEventListener();
	}

	public ListenerSet<TraceRecorderListener> getListeners() {
		return objectManager.getListeners();
	}

	@Override
	public void addListener(TraceRecorderListener l) {
		getListeners().add(l);
	}

	@Override
	public void removeListener(TraceRecorderListener l) {
		getListeners().remove(l);
	}

	/*---------------- DELEGATED METHODS -------------------*/

	public AbstractRecorderMemory getProcessMemory() {
		return processRecorder.getProcessMemory();
	}

	@Override
	public AddressSetView getAccessibleProcessMemory() {
		return processRecorder.getAccessibleProcessMemory();
	}

	@Override
	public CompletableFuture<byte[]> readProcessMemory(Address start, int length) {
		return processRecorder.readProcessMemory(start, length);
	}

	@Override
	public CompletableFuture<Void> writeProcessMemory(Address start, byte[] data) {
		return processRecorder.writeProcessMemory(start, data);
	}

	@Override
	public CompletableFuture<Void> writeThreadRegisters(TraceThread thread, int frameLevel,
			Map<Register, RegisterValue> values) {
		DefaultThreadRecorder rec = getThreadRecorder(thread);
		return (rec == null) ? null : rec.writeThreadRegisters(frameLevel, values);
	}

	public TraceSnapshot getSnapshot() {
		return timeRecorder.getSnapshot();
	}

	public void createSnapshot(String description, TraceThread eventThread,
			RecorderPermanentTransaction tid) {
		timeRecorder.createSnapshot(description, eventThread, tid);
	}

	@Override
	public boolean isRegisterBankAccessible(TargetRegisterBank bank) {
		return true;
	}

	@Override
	public boolean isRegisterBankAccessible(TraceThread thread, int frameLevel) {
		return true;
	}

	@Override
	public CompletableFuture<Void> flushTransactions() {
		return parTx.flush();
	}
}
