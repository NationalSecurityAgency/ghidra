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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Predicate;

import docking.ActionContext;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.core.debug.gui.model.DebuggerObjectActionContext;
import ghidra.app.plugin.core.debug.service.target.AbstractTarget;
import ghidra.app.services.DebuggerConsoleService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.async.AsyncFence;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.TargetSteppable.TargetStepKind;
import ghidra.dbg.util.PathMatcher;
import ghidra.dbg.util.PathPredicates;
import ghidra.debug.api.model.TraceRecorder;
import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class TraceRecorderTarget extends AbstractTarget {
	private final TraceRecorder recorder;

	protected static boolean isSameFocus(DebuggerCoordinates prev, DebuggerCoordinates resolved) {
		if (!Objects.equals(prev.getObject(), resolved.getObject())) {
			return false;
		}
		if (!Objects.equals(prev.getFrame(), resolved.getFrame())) {
			return false;
		}
		if (!Objects.equals(prev.getThread(), resolved.getThread())) {
			return false;
		}
		if (!Objects.equals(prev.getTrace(), resolved.getTrace())) {
			return false;
		}
		return true;
	}

	protected static boolean checkTargetActivation(DebuggerCoordinates prev,
			DebuggerCoordinates resolved) {
		if (!resolved.isAlive()) {
			return false;
		}
		if (isSameFocus(prev, resolved)) {
			return false;
		}
		return true;
	}

	public TraceRecorderTarget(PluginTool tool, TraceRecorder recorder) {
		super(tool);
		this.recorder = recorder;
	}

	@Override
	public boolean isValid() {
		return recorder.isRecording();
	}

	protected <T extends TargetObject> T findObjectInContext(ActionContext context,
			Class<T> iface) {
		if (context instanceof DebuggerObjectActionContext ctx) {
			List<TraceObjectValue> values = ctx.getObjectValues();
			if (values.size() != 1) {
				return null;
			}
			TraceObjectValue single = values.get(0);
			if (!single.isObject()) {
				return null;
			}
			TraceObject suitable = single.getChild().querySuitableTargetInterface(iface);
			if (suitable == null) {
				return null;
			}
			return iface.cast(recorder.getTargetObject(suitable));
		}
		return null;
	}

	protected <T extends TargetObject> T findObjectInTrace(ActionContext context, Class<T> iface) {
		DebuggerTraceManagerService traceManager =
			tool.getService(DebuggerTraceManagerService.class);
		TraceObject focus = traceManager.getCurrentObject();
		if (focus == null) {
			return null;
		}
		TraceObject suitable = focus.querySuitableTargetInterface(iface);
		if (suitable == null) {
			return null;
		}
		return iface.cast(recorder.getTargetObject(suitable));
	}

	protected <T extends TargetObject> T findObjectInRecorder(ActionContext context,
			Class<T> iface) {
		if (!isValid()) {
			return null;
		}
		TargetObject focus = recorder.getFocus();
		if (focus == null) {
			return null;
		}
		return focus.getCachedSuitable(iface);
	}

	protected <T extends TargetObject> T findObject(ActionContext context, Class<T> iface) {
		T object = findObjectInContext(context, iface);
		if (object != null) {
			return object;
		}
		object = findObjectInTrace(context, iface);
		if (object != null) {
			return object;
		}
		return findObjectInRecorder(context, iface);
	}

	private Map<String, Object> collectArgumentsReqAddr(TargetParameterMap params,
			Address address) {
		// The only required non-defaulted argument allowed must be an Address
		// There must be an Address parameter
		ParameterDescription<?> addrParam = null;
		for (ParameterDescription<?> p : params.values()) {
			if (p.type == Address.class) {
				if (addrParam != null) {
					return null;
				}
				addrParam = p;
			}
			else if (p.required && p.defaultValue == null) {
				return null;
			}
		}
		if (addrParam == null) {
			return null;
		}
		return Map.of(addrParam.name, address);
	}

	private record MethodWithArgs(TargetMethod method, Map<String, Object> arguments) {
	}

	private List<MethodWithArgs> findAddressMethods(ProgramLocationActionContext context) {
		Address address = findAddress(context);
		if (address == null) {
			return List.of();
		}
		TargetObject object = findObject(context, TargetObject.class);
		if (object == null) {
			return List.of();
		}

		List<MethodWithArgs> result = new ArrayList<>();
		PathPredicates matcher = object.getModel()
				.getRootSchema()
				.matcherForSuitable(TargetMethod.class, object.getPath());
		for (TargetObject obj : matcher.getCachedSuccessors(object.getModel().getModelRoot())
				.values()) {
			if (!(obj instanceof TargetMethod method)) {
				continue;
			}
			Map<String, Object> arguments =
				collectArgumentsReqAddr(method.getParameters(), address);
			if (arguments == null) {
				continue;
			}
			result.add(new MethodWithArgs(method, arguments));
		}
		return result;
	}

	private static String getDisplay(TargetMethod method) {
		String display = method.getDisplay();
		if (display != null) {
			return display;
		}
		return method.getName();
	}

	private ActionEntry makeEntry(TargetMethod method, Map<String, ?> arguments) {
		return new ActionEntry(method.getDisplay(), null, null, false, () -> true, () -> {
			return method.invoke(arguments).thenAccept(result -> {
				DebuggerConsoleService consoleService =
					tool.getService(DebuggerConsoleService.class);
				if (consoleService != null && method.getReturnType() != Void.class) {
					consoleService.log(null, getDisplay(method) + " returned " + result);
				}
			});
		});
	}

	@Override
	public Map<String, ActionEntry> collectAddressActions(ProgramLocationActionContext context) {
		Map<String, ActionEntry> result = new HashMap<>();
		for (MethodWithArgs mwa : findAddressMethods(context)) {
			result.put(mwa.method.getJoinedPath("."), makeEntry(mwa.method, mwa.arguments));
		}
		return result;
	}

	protected <T extends TargetObject> Map<String, ActionEntry> collectIfaceActions(
			ActionContext context, Class<T> iface, String display, ActionName name,
			String description, Predicate<T> enabled, Function<T, CompletableFuture<?>> action) {
		T object = findObject(context, iface);
		if (object == null) {
			return Map.of();
		}
		return Map.of(display, new ActionEntry(display, name, description, false,
			() -> enabled.test(object), () -> action.apply(object)));
	}

	private TargetExecutionState getStateOf(TargetObject object) {
		TargetExecutionStateful stateful = object.getCachedSuitable(TargetExecutionStateful.class);
		return stateful == null ? null : stateful.getExecutionState();
	}

	private <T extends TargetObject> Predicate<T> stateNullOr(
			Predicate<TargetExecutionState> predicate) {
		return object -> {
			TargetExecutionState state = getStateOf(object);
			return state == null || predicate.test(state);
		};
	}

	@Override
	protected Map<String, ActionEntry> collectResumeActions(ActionContext context) {
		return collectIfaceActions(context, TargetResumable.class, "Resume",
			ActionName.RESUME, "Resume, i.e., go or continue execution of the target",
			stateNullOr(TargetExecutionState::isStopped), TargetResumable::resume);
	}

	@Override
	protected Map<String, ActionEntry> collectInterruptActions(ActionContext context) {
		return collectIfaceActions(context, TargetInterruptible.class, "Interrupt",
			ActionName.INTERRUPT, "Interrupt, i.e., suspend, the target",
			stateNullOr(TargetExecutionState::isRunning), TargetInterruptible::interrupt);
	}

	@Override
	protected Map<String, ActionEntry> collectKillActions(ActionContext context) {
		return collectIfaceActions(context, TargetKillable.class, "Kill",
			ActionName.KILL, "Kill, i.e., forcibly terminate the target",
			stateNullOr(TargetExecutionState::isAlive), TargetKillable::kill);
	}

	@Override
	protected Map<String, ActionEntry> collectStepIntoActions(ActionContext context) {
		return collectIfaceActions(context, TargetSteppable.class, "Step Into",
			ActionName.STEP_INTO, "Step the target a single instruction, descending into calls",
			stateNullOr(TargetExecutionState::isStopped),
			steppable -> steppable.step(TargetStepKind.INTO));
	}

	@Override
	protected Map<String, ActionEntry> collectStepOverActions(ActionContext context) {
		return collectIfaceActions(context, TargetSteppable.class, "Step Over",
			ActionName.STEP_OVER, "Step the target a single instruction, without following calls",
			stateNullOr(TargetExecutionState::isStopped),
			steppable -> steppable.step(TargetStepKind.OVER));
	}

	@Override
	protected Map<String, ActionEntry> collectStepOutActions(ActionContext context) {
		return collectIfaceActions(context, TargetSteppable.class, "Step Out",
			ActionName.STEP_OUT, "Step the target until it completes the current frame",
			stateNullOr(TargetExecutionState::isStopped),
			steppable -> steppable.step(TargetStepKind.FINISH));
	}

	@Override
	protected Map<String, ActionEntry> collectStepExtActions(ActionContext context) {
		return collectIfaceActions(context, TargetSteppable.class, "Step Last",
			ActionName.STEP_EXT, "Step the target in a target-defined way",
			stateNullOr(TargetExecutionState::isStopped),
			steppable -> steppable.step(TargetStepKind.EXTENDED));
	}

	@Override
	public Trace getTrace() {
		return recorder.getTrace();
	}

	@Override
	public long getSnap() {
		return recorder.getSnap();
	}

	@Override
	public TargetExecutionState getThreadExecutionState(TraceThread thread) {
		return recorder.getTargetThreadState(thread);
	}

	@Override
	public boolean isSupportsFocus() {
		return recorder.isSupportsFocus();
	}

	@Override
	public TraceObjectKeyPath getFocus() {
		TargetObject object = recorder.getFocus();
		if (object == null) {
			return null;
		}
		return TraceObjectKeyPath.of(object.getPath());
	}

	protected TargetObject toTargetObject(DebuggerCoordinates coords) {
		TraceObject obj = coords.getObject();
		if (obj != null) {
			TargetObject object =
				recorder.getTarget().getSuccessor(obj.getCanonicalPath().getKeyList());
			if (object != null) {
				return object;
			}
		}
		TargetStackFrame frame =
			recorder.getTargetStackFrame(coords.getThread(), coords.getFrame());
		if (frame != null) {
			return frame;
		}
		TargetThread thread = recorder.getTargetThread(coords.getThread());
		if (thread != null) {
			return thread;
		}
		return recorder.getTarget();
	}

	@Override
	public CompletableFuture<Void> activateAsync(DebuggerCoordinates prev,
			DebuggerCoordinates coords) {
		if (!checkTargetActivation(prev, coords)) {
			return AsyncUtils.nil();
		}

		if (!recorder.isRecording() || recorder.getSnap() != coords.getSnap() ||
			!coords.getTime().isSnapOnly()) {
			return AsyncUtils.nil();
		}
		TargetObject obj = toTargetObject(coords);
		if (obj == null) {
			return AsyncUtils.nil();
		}
		return recorder.requestActivation(obj).thenApply(__ -> null);
	}

	@Override
	public TraceThread getThreadForSuccessor(TraceObjectKeyPath path) {
		if (path == null) {
			return null;
		}
		TargetObject object = recorder.getTargetObject(path);
		if (object == null) {
			return null;
		}
		return recorder.getTraceThreadForSuccessor(object);
	}

	@Override
	public TraceStackFrame getStackFrameForSuccessor(TraceObjectKeyPath path) {
		if (path == null) {
			return null;
		}
		TargetObject object = recorder.getTargetObject(path);
		if (object == null) {
			return null;
		}
		return recorder.getTraceStackFrameForSuccessor(object);
	}

	@Override
	public CompletableFuture<Void> invalidateMemoryCachesAsync() {
		TargetObject target = recorder.getTarget();
		DebuggerObjectModel model = target.getModel();
		model.invalidateAllLocalCaches();
		PathMatcher memMatcher = target.getSchema().searchFor(TargetMemory.class, true);
		Collection<TargetObject> memories = memMatcher.getCachedSuccessors(target).values();
		CompletableFuture<?>[] requests = memories.stream()
				.map(TargetObject::invalidateCaches)
				.toArray(CompletableFuture[]::new);
		return CompletableFuture.allOf(requests);
	}

	@Override
	public CompletableFuture<Void> readMemoryAsync(AddressSetView set, TaskMonitor monitor) {
		return recorder.readMemoryBlocks(set, monitor)
				.thenCompose(__ -> recorder.getTarget().getModel().flushEvents())
				.thenCompose(__ -> recorder.flushTransactions())
				.thenAccept(__ -> recorder.getTrace().flushEvents());
	}

	@Override
	public CompletableFuture<Void> readRegistersAsync(TracePlatform platform, TraceThread thread,
			int frame, Set<Register> registers) {
		if (registers.isEmpty()) {
			return AsyncUtils.nil();
		}
		return recorder.captureThreadRegisters(platform, thread, frame, registers)
				.thenCompose(__ -> recorder.getTarget().getModel().flushEvents())
				.thenCompose(__ -> recorder.flushTransactions())
				.thenAccept(__ -> platform.getTrace().flushEvents());
	}

	@Override
	public boolean isVariableExists(TracePlatform platform, TraceThread thread, int frame,
			Address address, int length) {
		return recorder.isVariableOnTarget(platform, thread, frame, address, length);
	}

	@Override
	public CompletableFuture<Void> writeMemoryAsync(Address address, byte[] data) {
		return recorder.writeMemory(address, data)
				.thenCompose(__ -> recorder.getTarget().getModel().flushEvents())
				.thenCompose(__ -> recorder.flushTransactions())
				.thenAccept(__ -> recorder.getTrace().flushEvents());
	}

	@Override
	public CompletableFuture<Void> writeRegisterAsync(TracePlatform platform, TraceThread thread,
			int frame, RegisterValue value) {
		return recorder.writeThreadRegisters(platform, thread, frame,
			Map.of(value.getRegister(), value))
				.thenCompose(__ -> recorder.getTarget().getModel().flushEvents())
				.thenCompose(__ -> recorder.flushTransactions())
				.thenAccept(__ -> recorder.getTrace().flushEvents());
	}

	@Override
	public CompletableFuture<Void> writeRegisterAsync(TracePlatform platform, TraceThread thread,
			int frame, Address address, byte[] data) {
		return recorder.writeRegister(platform, thread, frame, address, data)
				.thenCompose(__ -> recorder.getTarget().getModel().flushEvents())
				.thenCompose(__ -> recorder.flushTransactions())
				.thenAccept(__ -> recorder.getTrace().flushEvents());
	}

	@Override
	public CompletableFuture<Void> writeVariableAsync(TracePlatform platform, TraceThread thread,
			int frame, Address address, byte[] data) {
		return recorder.writeVariable(platform, thread, frame, address, data);
	}

	@Override
	public CompletableFuture<Void> placeBreakpointAsync(AddressRange range,
			Set<TraceBreakpointKind> kinds, String condition, String commands) {
		if (condition != null && !condition.isBlank()) {
			Msg.warn(this, "breakpoint condition not supported by recorder-based targets");
		}
		if (commands != null && !commands.isBlank()) {
			Msg.warn(this, "breakpoint commands not supported by recorder-based targets");
		}
		Set<TargetBreakpointKind> tKinds =
			TraceRecorder.traceToTargetBreakpointKinds(kinds);
		AddressRange targetRange = recorder.getMemoryMapper().traceToTarget(range);
		AsyncFence fence = new AsyncFence();
		for (TargetBreakpointSpecContainer cont : recorder.collectBreakpointContainers(null)) {
			Set<TargetBreakpointKind> stKinds = new LinkedHashSet<>(tKinds);
			stKinds.retainAll(cont.getSupportedBreakpointKinds());
			fence.include(cont.placeBreakpoint(targetRange, stKinds));
		}
		return fence.ready();
	}

	@Override
	public Set<TraceBreakpointKind> getSupportedBreakpointKinds() {
		return recorder.getSupportedBreakpointKinds();
	}

	@Override
	public boolean isBreakpointValid(TraceBreakpoint breakpoint) {
		return recorder.getTargetBreakpoint(breakpoint) != null;
	}

	@Override
	public CompletableFuture<Void> deleteBreakpointAsync(TraceBreakpoint breakpoint) {
		TargetBreakpointLocation loc = recorder.getTargetBreakpoint(breakpoint);
		if (loc == null) {
			Msg.warn(this, "Breakpoint not valid on target: " + loc);
			return AsyncUtils.nil();
		}
		if (loc instanceof TargetDeletable del) {
			return del.delete();
		}
		TargetBreakpointSpec spec = loc.getSpecification();
		if (spec instanceof TargetDeletable del) {
			return del.delete();
		}
		Msg.warn(this, "Neither location nor specification for breakpoint is deletable: " + loc);
		return AsyncUtils.nil();
	}

	@Override
	public CompletableFuture<Void> toggleBreakpointAsync(TraceBreakpoint breakpoint,
			boolean enabled) {
		TargetBreakpointLocation loc = recorder.getTargetBreakpoint(breakpoint);
		if (loc == null) {
			Msg.warn(this, "Breakpoint not valid on target: " + loc);
			return AsyncUtils.nil();
		}
		if (loc instanceof TargetTogglable tog) {
			return tog.toggle(enabled);
		}
		TargetBreakpointSpec spec = loc.getSpecification();
		return spec.toggle(enabled);
	}

	@Override
	public CompletableFuture<Void> disconnectAsync() {
		return recorder.getTarget()
				.getModel()
				.close()
				.orTimeout(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
	}
}
