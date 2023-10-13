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
package ghidra.app.plugin.core.debug.service.rmi.trace;

import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.function.BooleanSupplier;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.apache.commons.lang3.exception.ExceptionUtils;

import docking.ActionContext;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.core.debug.gui.model.DebuggerObjectActionContext;
import ghidra.app.plugin.core.debug.service.target.AbstractTarget;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.async.*;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.util.PathMatcher;
import ghidra.dbg.util.PathPredicates;
import ghidra.dbg.util.PathPredicates.Align;
import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.debug.api.tracermi.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.stack.*;
import ghidra.trace.model.target.*;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class TraceRmiTarget extends AbstractTarget {
	private static final String BREAK_HW_EXEC = "breakHwExec";
	private static final String BREAK_SW_EXEC = "breakSwExec";
	private static final String BREAK_READ = "breakRead";
	private static final String BREAK_WRITE = "breakWrite";
	private static final String BREAK_ACCESS = "breakAccess";
	private final TraceRmiConnection connection;
	private final Trace trace;

	private final Matches matches = new Matches();
	private final Set<TraceBreakpointKind> supportedBreakpointKinds;

	public TraceRmiTarget(PluginTool tool, TraceRmiConnection connection, Trace trace) {
		super(tool);
		this.connection = connection;
		this.trace = trace;
		this.supportedBreakpointKinds = computeSupportedBreakpointKinds();
	}

	@Override
	public boolean isValid() {
		return !connection.isClosed();
	}

	@Override
	public Trace getTrace() {
		return trace;
	}

	@Override
	public long getSnap() {
		return connection.getLastSnapshot(trace);
	}

	@Override
	public TargetExecutionState getThreadExecutionState(TraceThread thread) {
		if (!(thread instanceof TraceObjectThread tot)) {
			Msg.error(this, "Non-object thread with Trace RMI!");
			return TargetExecutionState.ALIVE;
		}
		return tot.getObject().getExecutionState(getSnap());
	}

	@Override
	public TraceThread getThreadForSuccessor(TraceObjectKeyPath path) {
		TraceObject object = trace.getObjectManager().getObjectByCanonicalPath(path);
		if (object == null) {
			return null;
		}
		return object.queryCanonicalAncestorsInterface(TraceObjectThread.class)
				.findFirst()
				.orElse(null);
	}

	@Override
	public TraceStackFrame getStackFrameForSuccessor(TraceObjectKeyPath path) {
		TraceObject object = trace.getObjectManager().getObjectByCanonicalPath(path);
		if (object == null) {
			return null;
		}
		return object.queryCanonicalAncestorsInterface(TraceObjectStackFrame.class)
				.findFirst()
				.orElse(null);
	}

	protected TraceObject findObject(ActionContext context) {
		if (context instanceof DebuggerObjectActionContext ctx) {
			List<TraceObjectValue> values = ctx.getObjectValues();
			if (values.size() == 1) {
				TraceObjectValue ov = values.get(0);
				if (ov.isObject()) {
					return ov.getChild();
				}
			}
		}
		DebuggerTraceManagerService traceManager =
			tool.getService(DebuggerTraceManagerService.class);
		if (traceManager != null) {
			return traceManager.getCurrentObject();
		}
		return null;
	}

	protected Object findArgumentForSchema(ActionContext context, TargetObjectSchema schema) {
		if (schema instanceof EnumerableTargetObjectSchema prim) {
			return switch (prim) {
				case OBJECT -> findObject(context);
				case ADDRESS -> findAddress(context);
				case RANGE -> findRange(context);
				default -> null;
			};
		}
		TraceObject object = findObject(context);
		if (object == null) {
			return null;
		}
		return object.querySuitableSchema(schema);
	}

	private enum Missing {
		MISSING; // The argument requires a prompt
	}

	protected Object findArgument(RemoteParameter parameter, ActionContext context) {
		SchemaName type = parameter.type();
		TargetObjectSchema schema = getSchemaContext().getSchema(type);
		if (schema == null) {
			Msg.error(this, "Schema " + type + " not in trace! " + trace);
			return null;
		}
		Object arg = findArgumentForSchema(context, schema);
		if (arg != null) {
			return arg;
		}
		if (!parameter.required()) {
			return parameter.getDefaultValue();
		}
		return Missing.MISSING;
	}

	protected Map<String, Object> collectArguments(RemoteMethod method, ActionContext context) {
		return method.parameters()
				.entrySet()
				.stream()
				.collect(
					Collectors.toMap(Entry::getKey, e -> findArgument(e.getValue(), context)));
	}

	private TargetExecutionState getStateOf(TraceObject object) {
		return object.getExecutionState(getSnap());
	}

	private boolean stateOrNull(TraceObject object,
			Predicate<TargetExecutionState> predicate) {
		TargetExecutionState state = getStateOf(object);
		return state == null || predicate.test(state);
	}

	protected BooleanSupplier chooseEnabler(RemoteMethod method, Map<String, Object> args) {
		ActionName name = method.action();
		SchemaContext ctx = getSchemaContext();
		RemoteParameter firstParam = method.parameters()
				.values()
				.stream()
				.filter(p -> TargetObject.class.isAssignableFrom(ctx.getSchema(p.type()).getType()))
				.findFirst()
				.orElse(null);
		if (firstParam == null) {
			return () -> true;
		}
		TraceObject firstArg = (TraceObject) args.get(firstParam.name());
		if (ActionName.RESUME.equals(name) ||
			ActionName.STEP_BACK.equals(name) ||
			ActionName.STEP_EXT.equals(name) ||
			ActionName.STEP_INTO.equals(name) ||
			ActionName.STEP_OUT.equals(name) ||
			ActionName.STEP_OVER.equals(name) ||
			ActionName.STEP_SKIP.equals(name)) {
			return () -> stateOrNull(firstArg, TargetExecutionState::isStopped);
		}
		else if (ActionName.INTERRUPT.equals(name)) {
			return () -> stateOrNull(firstArg, TargetExecutionState::isRunning);
		}
		else if (ActionName.KILL.equals(name)) {
			return () -> stateOrNull(firstArg, TargetExecutionState::isAlive);
		}
		return () -> true;
	}

	protected ActionEntry createEntry(RemoteMethod method, ActionContext context) {
		Map<String, Object> args = collectArguments(method, context);
		boolean requiresPrompt = args.values().contains(Missing.MISSING);
		return new ActionEntry(method.name(), method.action(), method.description(), requiresPrompt,
			chooseEnabler(method, args), () -> method.invokeAsync(args).toCompletableFuture());
	}

	protected Map<String, ActionEntry> collectFromMethods(Collection<RemoteMethod> methods,
			ActionContext context) {
		Map<String, ActionEntry> result = new HashMap<>();
		for (RemoteMethod m : methods) {
			result.put(m.name(), createEntry(m, context));
		}
		return result;
	}

	protected boolean isAddressMethod(RemoteMethod method, SchemaContext ctx) {
		return method.parameters()
				.values()
				.stream()
				.filter(p -> ctx.getSchema(p.type()).getType() == Address.class)
				.count() == 1;
	}

	@Override
	protected Map<String, ActionEntry> collectAddressActions(ProgramLocationActionContext context) {
		SchemaContext ctx = getSchemaContext();
		Map<String, ActionEntry> result = new HashMap<>();
		for (RemoteMethod m : connection.getMethods().all().values()) {
			if (!isAddressMethod(m, ctx)) {
				continue;
			}
			result.put(m.name(), createEntry(m, context));
		}
		return result;
	}

	@Override
	protected Map<String, ActionEntry> collectAllActions(ActionContext context) {
		return collectFromMethods(connection.getMethods().all().values(), context);
	}

	protected Map<String, ActionEntry> collectByName(ActionName name, ActionContext context) {
		return collectFromMethods(connection.getMethods().getByAction(name), context);
	}

	@Override
	protected Map<String, ActionEntry> collectResumeActions(ActionContext context) {
		return collectByName(ActionName.RESUME, context);
	}

	@Override
	protected Map<String, ActionEntry> collectInterruptActions(ActionContext context) {
		return collectByName(ActionName.INTERRUPT, context);
	}

	@Override
	protected Map<String, ActionEntry> collectKillActions(ActionContext context) {
		return collectByName(ActionName.KILL, context);
	}

	@Override
	protected Map<String, ActionEntry> collectStepIntoActions(ActionContext context) {
		return collectByName(ActionName.STEP_INTO, context);
	}

	@Override
	protected Map<String, ActionEntry> collectStepOverActions(ActionContext context) {
		return collectByName(ActionName.STEP_OVER, context);
	}

	@Override
	protected Map<String, ActionEntry> collectStepOutActions(ActionContext context) {
		return collectByName(ActionName.STEP_OUT, context);
	}

	@Override
	protected Map<String, ActionEntry> collectStepExtActions(ActionContext context) {
		return collectByName(ActionName.STEP_EXT, context);
	}

	@Override
	public boolean isSupportsFocus() {
		TargetObjectSchema schema = trace.getObjectManager().getRootSchema();
		if (schema == null) {
			Msg.warn(this, "Checked for focus support before root schema is available");
			return false;
		}
		return schema
				.getInterfaces()
				.contains(TargetFocusScope.class) &&
			!connection.getMethods().getByAction(ActionName.ACTIVATE).isEmpty();
	}

	@Override
	public TraceObjectKeyPath getFocus() {
		TraceObjectValue focusVal = trace.getObjectManager()
				.getRootObject()
				.getAttribute(getSnap(), TargetFocusScope.FOCUS_ATTRIBUTE_NAME);
		if (focusVal == null || !focusVal.isObject()) {
			return null;
		}
		return focusVal.getChild().getCanonicalPath();
	}

	interface MethodMatcher {
		default MatchedMethod match(RemoteMethod method, SchemaContext ctx) {
			List<ParamSpec> spec = spec();
			if (spec.size() != method.parameters().size()) {
				return null;
			}
			Map<String, RemoteParameter> found = new HashMap<>();
			for (ParamSpec ps : spec) {
				RemoteParameter param = ps.find(method, ctx);
				if (param == null) {
					return null;
				}
				found.put(ps.name(), param);
			}
			return new MatchedMethod(method, Map.copyOf(found), score());
		}

		List<ParamSpec> spec();

		int score();

		static MatchedMethod matchPreferredForm(RemoteMethod method, SchemaContext ctx,
				List<? extends MethodMatcher> preferred) {
			return preferred.stream()
					.map(m -> m.match(method, ctx))
					.filter(m -> m != null)
					.findFirst()
					.orElse(null);
		}
	}

	record MatchedMethod(RemoteMethod method, Map<String, RemoteParameter> params, int score)
			implements Comparable<MatchedMethod> {
		@Override
		public int compareTo(MatchedMethod that) {
			return Integer.compare(this.score, that.score);
		}
	}

	protected static boolean typeMatches(RemoteParameter param, SchemaContext ctx, Class<?> type) {
		TargetObjectSchema sch = ctx.getSchema(param.type());
		if (type == TargetObject.class) {
			return sch.getType() == type;
		}
		else if (TargetObject.class.isAssignableFrom(type)) {
			return sch.getInterfaces().contains(type);
		}
		else {
			return sch.getType() == type;
		}
	}

	interface ParamSpec {
		String name();

		RemoteParameter find(RemoteMethod method, SchemaContext ctx);
	}

	record TypeParamSpec(String name, Class<?> type) implements ParamSpec {
		@Override
		public RemoteParameter find(RemoteMethod method, SchemaContext ctx) {
			List<RemoteParameter> withType = method.parameters()
					.values()
					.stream()
					.filter(p -> typeMatches(p, ctx, type))
					.toList();
			if (withType.size() != 1) {
				return null;
			}
			return withType.get(0);
		}
	}

	record NameParamSpec(String name, Class<?> type) implements ParamSpec {
		@Override
		public RemoteParameter find(RemoteMethod method, SchemaContext ctx) {
			RemoteParameter param = method.parameters().get(name);
			if (typeMatches(param, ctx, type)) {
				return param;
			}
			return null;
		}
	}

	@SafeVarargs
	protected static <T extends MethodMatcher> List<T> matchers(T... list) {
		List<T> result = List.of(list);
		result.sort(Comparator.comparing(MethodMatcher::score).reversed());
		if (result.isEmpty()) {
			throw new AssertionError("empty matchers list?");
		}
		int prevScore = result.get(0).score();
		for (int i = 1; i < result.size(); i++) {
			int curScore = result.get(i).score();
			if (prevScore <= curScore) {
				throw new AssertionError("duplicate scores: " + curScore);
			}
		}
		return result;
	}

	record ActivateMatcher(int score, List<ParamSpec> spec) implements MethodMatcher {
		static final ActivateMatcher HAS_FOCUS_TIME = new ActivateMatcher(3, List.of(
			new TypeParamSpec("focus", TargetObject.class),
			new TypeParamSpec("time", String.class)));
		static final ActivateMatcher HAS_FOCUS_SNAP = new ActivateMatcher(2, List.of(
			new TypeParamSpec("focus", TargetObject.class),
			new TypeParamSpec("snap", Long.class)));
		static final ActivateMatcher HAS_FOCUS = new ActivateMatcher(1, List.of(
			new TypeParamSpec("focus", TargetObject.class)));
		static final List<ActivateMatcher> ALL =
			matchers(HAS_FOCUS_TIME, HAS_FOCUS_SNAP, HAS_FOCUS);
	}

	record ReadMemMatcher(int score, List<ParamSpec> spec) implements MethodMatcher {
		static final ReadMemMatcher HAS_RANGE = new ReadMemMatcher(1, List.of(
			new TypeParamSpec("range", AddressRange.class)));
		static final List<ReadMemMatcher> ALL = matchers(HAS_RANGE);
	}

	record WriteMemMatcher(int score, List<ParamSpec> spec) implements MethodMatcher {
		static final WriteMemMatcher HAS_RANGE = new WriteMemMatcher(1, List.of(
			new TypeParamSpec("start", Address.class),
			new TypeParamSpec("data", byte[].class)));
		static final List<WriteMemMatcher> ALL = matchers(HAS_RANGE);
	}

	record ReadRegsMatcher(int score, List<ParamSpec> spec) implements MethodMatcher {
		static final ReadRegsMatcher HAS_CONTAINER = new ReadRegsMatcher(3, List.of(
			new TypeParamSpec("container", TargetRegisterContainer.class)));
		static final ReadRegsMatcher HAS_BANK = new ReadRegsMatcher(2, List.of(
			new TypeParamSpec("bank", TargetRegisterBank.class)));
		static final ReadRegsMatcher HAS_REGISTER = new ReadRegsMatcher(1, List.of(
			new TypeParamSpec("register", TargetRegister.class)));
		static final List<ReadRegsMatcher> ALL = matchers(HAS_CONTAINER, HAS_BANK, HAS_REGISTER);
	}

	record WriteRegMatcher(int score, List<ParamSpec> spec) implements MethodMatcher {
		static final WriteRegMatcher HAS_FRAME_NAME_VALUE = new WriteRegMatcher(2, List.of(
			new TypeParamSpec("frame", TargetStackFrame.class),
			new TypeParamSpec("name", String.class),
			new TypeParamSpec("value", byte[].class)));
		static final WriteRegMatcher HAS_REG_VALUE = new WriteRegMatcher(1, List.of(
			new TypeParamSpec("register", TargetRegister.class),
			new TypeParamSpec("value", byte[].class)));
		static final List<WriteRegMatcher> ALL = matchers(HAS_FRAME_NAME_VALUE, HAS_REG_VALUE);
	}

	record BreakExecMatcher(int score, List<ParamSpec> spec) implements MethodMatcher {
		static final BreakExecMatcher HAS_ADDR_COND_CMDS = new BreakExecMatcher(4, List.of(
			new TypeParamSpec("address", Address.class),
			new NameParamSpec("condition", String.class),
			new NameParamSpec("commands", String.class)));
		static final BreakExecMatcher HAS_ADDR_COND = new BreakExecMatcher(3, List.of(
			new TypeParamSpec("address", Address.class),
			new NameParamSpec("condition", String.class)));
		static final BreakExecMatcher HAS_ADDR_CMDS = new BreakExecMatcher(2, List.of(
			new TypeParamSpec("address", Address.class),
			new NameParamSpec("commands", String.class)));
		static final BreakExecMatcher HAS_ADDR = new BreakExecMatcher(1, List.of(
			new TypeParamSpec("address", Address.class)));
		static final List<BreakExecMatcher> ALL =
			matchers(HAS_ADDR_COND_CMDS, HAS_ADDR_COND, HAS_ADDR_CMDS, HAS_ADDR);
	}

	record BreakAccMatcher(int score, List<ParamSpec> spec) implements MethodMatcher {
		static final BreakAccMatcher HAS_RNG_COND_CMDS = new BreakAccMatcher(4, List.of(
			new TypeParamSpec("range", AddressRange.class),
			new NameParamSpec("condition", String.class),
			new NameParamSpec("commands", String.class)));
		static final BreakAccMatcher HAS_RNG_COND = new BreakAccMatcher(3, List.of(
			new TypeParamSpec("range", AddressRange.class),
			new NameParamSpec("condition", String.class)));
		static final BreakAccMatcher HAS_RNG_CMDS = new BreakAccMatcher(2, List.of(
			new TypeParamSpec("range", AddressRange.class),
			new NameParamSpec("commands", String.class)));
		static final BreakAccMatcher HAS_RNG = new BreakAccMatcher(1, List.of(
			new TypeParamSpec("range", AddressRange.class)));
		static final List<BreakAccMatcher> ALL =
			matchers(HAS_RNG_COND_CMDS, HAS_RNG_COND, HAS_RNG_CMDS, HAS_RNG);
	}

	record DelBreakMatcher(int score, List<ParamSpec> spec) implements MethodMatcher {
		static final DelBreakMatcher HAS_LOC = new DelBreakMatcher(2, List.of(
			new TypeParamSpec("location", TargetBreakpointLocation.class)));
		static final DelBreakMatcher HAS_SPEC = new DelBreakMatcher(1, List.of(
			new TypeParamSpec("specification", TargetBreakpointSpec.class)));
		static final List<DelBreakMatcher> ALL = matchers(HAS_LOC, HAS_SPEC);
		static final List<DelBreakMatcher> SPEC = matchers(HAS_SPEC);
	}

	record ToggleBreakMatcher(int score, List<ParamSpec> spec) implements MethodMatcher {
		static final ToggleBreakMatcher HAS_LOC = new ToggleBreakMatcher(2, List.of(
			new TypeParamSpec("location", TargetBreakpointLocation.class),
			new TypeParamSpec("enabled", Boolean.class)));
		static final ToggleBreakMatcher HAS_SPEC = new ToggleBreakMatcher(1, List.of(
			new TypeParamSpec("specification", TargetBreakpointSpec.class),
			new TypeParamSpec("enabled", Boolean.class)));
		static final List<ToggleBreakMatcher> ALL = matchers(HAS_LOC, HAS_SPEC);
		static final List<ToggleBreakMatcher> SPEC = matchers(HAS_SPEC);
	}

	protected class Matches {
		private final Map<String, MatchedMethod> map = new HashMap<>();

		public MatchedMethod getBest(String name, ActionName action,
				List<? extends MethodMatcher> preferred) {
			return map.computeIfAbsent(name, n -> chooseBest(action, preferred));
		}

		private MatchedMethod chooseBest(ActionName name, List<? extends MethodMatcher> preferred) {
			if (preferred.isEmpty()) {
				return null;
			}
			SchemaContext ctx = getSchemaContext();
			MatchedMethod best = connection.getMethods()
					.getByAction(name)
					.stream()
					.map(m -> MethodMatcher.matchPreferredForm(m, ctx, preferred))
					.filter(f -> f != null)
					.max(MatchedMethod::compareTo)
					.orElse(null);
			if (best == null) {
				Msg.error(this, "No suitable " + name + " method");
			}
			return best;
		}
	}

	@Override
	public CompletableFuture<Void> activateAsync(DebuggerCoordinates prev,
			DebuggerCoordinates coords) {
		MatchedMethod activate =
			matches.getBest("activate", ActionName.ACTIVATE, ActivateMatcher.ALL);
		if (activate == null) {
			return AsyncUtils.nil();
		}

		Map<String, Object> args = new HashMap<>();
		RemoteParameter paramFocus = activate.params.get("focus");
		args.put(paramFocus.name(), coords.getObject());
		RemoteParameter paramTime = activate.params.get("time");
		if (paramTime != null) {
			args.put(paramTime.name(), coords.getTime().toString());
		}
		RemoteParameter paramSnap = activate.params.get("snap");
		if (paramSnap != null) {
			args.put(paramSnap.name(), coords.getSnap());
		}
		return activate.method.invokeAsync(args).toCompletableFuture().thenApply(__ -> null);
	}

	@Override
	public CompletableFuture<Void> invalidateMemoryCachesAsync() {
		return AsyncUtils.nil();
	}

	protected static final int BLOCK_BITS = 12;
	protected static final int BLOCK_SIZE = 1 << BLOCK_BITS;
	protected static final long BLOCK_MASK = -1L << BLOCK_BITS;

	protected static AddressSetView quantize(AddressSetView set) {
		AddressSet result = new AddressSet();
		// Not terribly efficient, but this is one range most of the time
		for (AddressRange range : set) {
			AddressSpace space = range.getAddressSpace();
			Address min = space.getAddress(range.getMinAddress().getOffset() & BLOCK_MASK);
			Address max = space.getAddress(range.getMaxAddress().getOffset() | ~BLOCK_MASK);
			result.add(new AddressRangeImpl(min, max));
		}
		return result;
	}

	protected SchemaContext getSchemaContext() {
		return trace.getObjectManager().getRootSchema().getContext();
	}

	@Override
	public CompletableFuture<Void> readMemoryAsync(AddressSetView set, TaskMonitor monitor) {
		// I still separate into blocks, because I want user to be able to cancel
		// NOTE: I don't intend to warn about the number of requests.
		//   They're delivered in serial, and there's a cancel button that works

		MatchedMethod readMem = matches.getBest("readMem", ActionName.READ_MEM, ReadMemMatcher.ALL);
		if (readMem == null) {
			return AsyncUtils.nil();
		}
		RemoteParameter paramRange = readMem.params.get("range");

		int total = 0;
		AddressSetView quantized = quantize(set);
		for (AddressRange r : quantized) {
			total += Long.divideUnsigned(r.getLength() + BLOCK_SIZE - 1, BLOCK_SIZE);
		}
		monitor.initialize(total);
		monitor.setMessage("Reading memory");
		// NOTE: Don't read in parallel, lest we overload the connection
		return AsyncUtils.each(TypeSpec.VOID, quantized.iterator(), (r, loop) -> {
			AddressRangeChunker blocks = new AddressRangeChunker(r, BLOCK_SIZE);
			AsyncUtils.each(TypeSpec.VOID, blocks.iterator(), (blk, inner) -> {
				monitor.incrementProgress(1);
				RemoteAsyncResult future =
					readMem.method.invokeAsync(Map.of(paramRange.name(), blk));
				future.exceptionally(e -> {
					Msg.error(this, "Could not read " + blk + ": " + e);
					return null; // Continue looping on errors
				}).thenApply(__ -> !monitor.isCancelled()).handle(inner::repeatWhile);
			}).thenApply(v -> !monitor.isCancelled()).handle(loop::repeatWhile);
		});
	}

	@Override
	public CompletableFuture<Void> writeMemoryAsync(Address address, byte[] data) {
		MatchedMethod writeMem =
			matches.getBest("writeMem", ActionName.WRITE_MEM, WriteMemMatcher.ALL);
		if (writeMem == null) {
			return AsyncUtils.nil();
		}
		Map<String, Object> args = new HashMap<>();
		args.put(writeMem.params.get("start").name(), address);
		args.put(writeMem.params.get("data").name(), data);
		return writeMem.method.invokeAsync(args).toCompletableFuture().thenApply(__ -> null);
	}

	@Override
	public CompletableFuture<Void> readRegistersAsync(TracePlatform platform, TraceThread thread,
			int frame, Set<Register> registers) {
		MatchedMethod readRegs =
			matches.getBest("readRegs", ActionName.REFRESH, ReadRegsMatcher.ALL);
		if (readRegs == null) {
			return AsyncUtils.nil();
		}
		if (!(thread instanceof TraceObjectThread tot)) {
			Msg.error(this, "Non-object trace with TraceRmi!");
			return AsyncUtils.nil();
		}
		TraceObject container = tot.getObject().queryRegisterContainer(frame);
		RemoteParameter paramContainer = readRegs.params.get("container");
		if (paramContainer != null) {
			return readRegs.method.invokeAsync(Map.of(paramContainer.name(), container))
					.toCompletableFuture()
					.thenApply(__ -> null);
		}
		Set<String> keys = new HashSet<>();
		for (Register r : registers) {
			String lower = r.getName().toLowerCase();
			keys.add(lower);
			keys.add("[" + lower + "]");
		}
		Set<TraceObject> regs = container
				.querySuccessorsTargetInterface(Lifespan.at(getSnap()), TargetRegister.class,
					true)
				.filter(p -> keys.contains(p.getLastEntry().getEntryKey().toLowerCase()))
				.map(r -> r.getDestination(null))
				.collect(Collectors.toSet());
		RemoteParameter paramBank = readRegs.params.get("bank");
		if (paramBank != null) {
			Set<TraceObject> banks = regs.stream()
					.flatMap(r -> r.queryCanonicalAncestorsTargetInterface(TargetRegisterBank.class)
							.findFirst()
							.stream())
					.collect(Collectors.toSet());
			AsyncFence fence = new AsyncFence();
			banks.stream().forEach(b -> {
				fence.include(
					readRegs.method.invokeAsync(Map.of(paramBank.name(), b)).toCompletableFuture());
			});
			return fence.ready();
		}
		RemoteParameter paramRegister = readRegs.params.get("register");
		if (paramRegister != null) {
			AsyncFence fence = new AsyncFence();
			regs.stream().forEach(r -> {
				fence.include(readRegs.method.invokeAsync(Map.of(paramRegister.name(), r))
						.toCompletableFuture());
			});
			return fence.ready();
		}
		throw new AssertionError();
	}

	protected TraceObject findRegisterObject(TraceObjectThread thread, int frame, String name) {
		TraceObject container = thread.getObject().queryRegisterContainer(frame);
		if (container == null) {
			Msg.error(this, "No register container for thread=" + thread + ",frame=" + frame);
			return null;
		}
		PathMatcher matcher = container.getTargetSchema().searchFor(TargetRegister.class, true);
		PathPredicates pred = matcher.applyKeys(Align.RIGHT, name)
				.or(matcher.applyKeys(Align.RIGHT, name.toLowerCase()))
				.or(matcher.applyKeys(Align.RIGHT, name.toUpperCase()));
		TraceObjectValPath regValPath =
			container.getCanonicalSuccessors(pred).findFirst().orElse(null);
		if (regValPath == null) {
			Msg.error(this, "Cannot find register object for " + name + " in " + container);
			return null;
		}
		return regValPath.getDestination(container);
	}

	@Override
	public CompletableFuture<Void> writeRegisterAsync(TracePlatform platform, TraceThread thread,
			int frame, RegisterValue value) {
		MatchedMethod writeReg =
			matches.getBest("writeReg", ActionName.WRITE_REG, WriteRegMatcher.ALL);
		if (writeReg == null) {
			return AsyncUtils.nil();
		}
		if (!(thread instanceof TraceObjectThread tot)) {
			Msg.error(this, "Non-object trace with TraceRmi!");
			return AsyncUtils.nil();
		}
		Register register = value.getRegister();
		String regName = register.getName();
		byte[] data =
			Utils.bigIntegerToBytes(value.getUnsignedValue(), register.getMinimumByteSize(), true);

		RemoteParameter paramFrame = writeReg.params.get("frame");
		if (paramFrame != null) {
			TraceStack stack = trace.getStackManager().getLatestStack(thread, getSnap());
			TraceStackFrame frameObj = stack.getFrame(frame, false);
			return writeReg.method.invokeAsync(Map.ofEntries(
				Map.entry(paramFrame.name(), frameObj),
				Map.entry(writeReg.params.get("name").name(), regName),
				Map.entry(writeReg.params.get("data").name(), data)))
					.toCompletableFuture()
					.thenApply(__ -> null);
		}
		TraceObject regObj = findRegisterObject(tot, frame, regName);
		if (regObj == null) {
			return AsyncUtils.nil();
		}
		return writeReg.method.invokeAsync(Map.ofEntries(
			Map.entry(writeReg.params.get("frame").name(), regObj),
			Map.entry(writeReg.params.get("data").name(), data)))
				.toCompletableFuture()
				.thenApply(__ -> null);
	}

	protected boolean isMemorySpaceValid(AddressSpace space) {
		return trace.getBaseAddressFactory().getAddressSpace(space.getSpaceID()) == space;
	}

	protected boolean isRegisterValid(TracePlatform platform, TraceThread thread, int frame,
			Address address, int length) {
		if (!isMemorySpaceValid(address.getAddressSpace())) {
			return false;
		}
		Register register =
			platform.getLanguage().getRegister(address.getPhysicalAddress(), length);
		if (register == null) {
			return false;
		}
		if (!(thread instanceof TraceObjectThread tot)) {
			return false;
		}
		TraceObject regObj = findRegisterObject(tot, frame, register.getName());
		if (regObj == null) {
			return false;
		}
		return true;
	}

	@Override
	public boolean isVariableExists(TracePlatform platform, TraceThread thread, int frame,
			Address address, int length) {
		if (address.isMemoryAddress()) {
			return isMemorySpaceValid(address.getAddressSpace());
		}
		if (address.isRegisterAddress()) {
			return isRegisterValid(platform, thread, frame, address, length);
		}
		return false;
	}

	@Override
	public CompletableFuture<Void> writeVariableAsync(TracePlatform platform, TraceThread thread,
			int frame, Address address, byte[] data) {
		if (address.isMemoryAddress()) {
			return writeMemoryAsync(address, data);
		}
		if (address.isRegisterAddress()) {
			return writeRegisterAsync(platform, thread, frame, address, data);
		}
		Msg.error(this, "Address is neither memory nor register: " + address);
		return AsyncUtils.nil();
	}

	protected Address expectSingleAddr(AddressRange range, TraceBreakpointKind kind) {
		Address address = range.getMinAddress();
		if (range.getLength() != 1) {
			Msg.warn(this, "Expected single address for " + kind + " breakpoint. Got " + range +
				". Using " + address);
		}
		return address;
	}

	protected void putOptionalBreakArgs(Map<String, Object> args, MatchedMethod brk,
			String condition, String commands) {
		if (condition != null && !condition.isBlank()) {
			RemoteParameter paramCond = brk.params.get("condition");
			if (paramCond == null) {
				Msg.error(this, "No condition parameter  on " + brk.method);
			}
			else {
				args.put(paramCond.name(), condition);
			}
		}
		if (commands != null && !commands.isBlank()) {
			RemoteParameter paramCmds = brk.params.get("commands");
			if (paramCmds == null) {
				Msg.error(this, "No commands parameter on " + brk.method);
			}
			else {
				args.put(paramCmds.name(), commands);
			}
		}
	}

	protected CompletableFuture<Void> doPlaceExecBreakAsync(MatchedMethod breakExec,
			Address address, String condition, String commands) {
		Map<String, Object> args = new HashMap<>();
		args.put(breakExec.params.get("address").name(), address);
		putOptionalBreakArgs(args, breakExec, condition, commands);
		return breakExec.method.invokeAsync(args).toCompletableFuture().thenApply(__ -> null);
	}

	protected CompletableFuture<Void> placeHwExecBreakAsync(Address address, String condition,
			String commands) {
		MatchedMethod breakHwExec =
			matches.getBest(BREAK_HW_EXEC, ActionName.BREAK_HW_EXECUTE, BreakExecMatcher.ALL);
		if (breakHwExec == null) {
			return AsyncUtils.nil();
		}
		return doPlaceExecBreakAsync(breakHwExec, address, condition, commands);
	}

	protected CompletableFuture<Void> placeSwExecBreakAsync(Address address, String condition,
			String commands) {
		MatchedMethod breakSwExec =
			matches.getBest(BREAK_SW_EXEC, ActionName.BREAK_SW_EXECUTE, BreakExecMatcher.ALL);
		if (breakSwExec == null) {
			return AsyncUtils.nil();
		}
		return doPlaceExecBreakAsync(breakSwExec, address, condition, commands);
	}

	protected CompletableFuture<Void> doPlaceAccBreakAsync(MatchedMethod breakAcc,
			AddressRange range, String condition, String commands) {
		Map<String, Object> args = new HashMap<>();
		args.put(breakAcc.params.get("range").name(), range);
		putOptionalBreakArgs(args, breakAcc, condition, commands);
		return breakAcc.method.invokeAsync(args).toCompletableFuture().thenApply(__ -> null);
	}

	protected CompletableFuture<Void> placeReadBreakAsync(AddressRange range, String condition,
			String commands) {
		MatchedMethod breakRead =
			matches.getBest(BREAK_READ, ActionName.BREAK_READ, BreakAccMatcher.ALL);
		if (breakRead == null) {
			return AsyncUtils.nil();
		}
		return doPlaceAccBreakAsync(breakRead, range, condition, commands);
	}

	protected CompletableFuture<Void> placeWriteBreakAsync(AddressRange range, String condition,
			String commands) {
		MatchedMethod breakWrite =
			matches.getBest(BREAK_WRITE, ActionName.BREAK_WRITE, BreakAccMatcher.ALL);
		if (breakWrite == null) {
			return AsyncUtils.nil();
		}
		return doPlaceAccBreakAsync(breakWrite, range, condition, commands);
	}

	protected CompletableFuture<Void> placeAccessBreakAsync(AddressRange range, String condition,
			String commands) {
		MatchedMethod breakAccess =
			matches.getBest(BREAK_ACCESS, ActionName.BREAK_ACCESS, BreakAccMatcher.ALL);
		if (breakAccess == null) {
			return AsyncUtils.nil();
		}
		return doPlaceAccBreakAsync(breakAccess, range, condition, commands);
	}

	@Override
	public CompletableFuture<Void> placeBreakpointAsync(AddressRange range,
			Set<TraceBreakpointKind> kinds, String condition, String commands) {
		Set<TraceBreakpointKind> copyKinds = Set.copyOf(kinds);
		if (copyKinds.equals(Set.of(TraceBreakpointKind.HW_EXECUTE))) {
			return placeHwExecBreakAsync(expectSingleAddr(range, TraceBreakpointKind.HW_EXECUTE),
				condition, commands);
		}
		if (copyKinds.equals(Set.of(TraceBreakpointKind.SW_EXECUTE))) {
			return placeSwExecBreakAsync(expectSingleAddr(range, TraceBreakpointKind.SW_EXECUTE),
				condition, commands);
		}
		if (copyKinds.equals(Set.of(TraceBreakpointKind.READ))) {
			return placeReadBreakAsync(range, condition, commands);
		}
		if (copyKinds.equals(Set.of(TraceBreakpointKind.WRITE))) {
			return placeWriteBreakAsync(range, condition, commands);
		}
		if (copyKinds.equals(Set.of(TraceBreakpointKind.READ, TraceBreakpointKind.WRITE))) {
			return placeAccessBreakAsync(range, condition, commands);
		}
		Msg.error(this, "Invalid kinds in combination: " + kinds);
		return AsyncUtils.nil();
	}

	protected Set<TraceBreakpointKind> computeSupportedBreakpointKinds() {
		Set<TraceBreakpointKind> result = new HashSet<>();
		RemoteMethodRegistry methods = connection.getMethods();
		if (!methods.getByAction(ActionName.BREAK_HW_EXECUTE).isEmpty()) {
			result.add(TraceBreakpointKind.HW_EXECUTE);
		}
		if (!methods.getByAction(ActionName.BREAK_SW_EXECUTE).isEmpty()) {
			result.add(TraceBreakpointKind.SW_EXECUTE);
		}
		if (!methods.getByAction(ActionName.BREAK_READ).isEmpty()) {
			result.add(TraceBreakpointKind.READ);
		}
		if (!methods.getByAction(ActionName.BREAK_WRITE).isEmpty()) {
			result.add(TraceBreakpointKind.WRITE);
		}
		if (!methods.getByAction(ActionName.BREAK_ACCESS).isEmpty()) {
			result.add(TraceBreakpointKind.READ);
			result.add(TraceBreakpointKind.WRITE);
		}
		return Set.copyOf(result);
	}

	@Override
	public Set<TraceBreakpointKind> getSupportedBreakpointKinds() {
		return supportedBreakpointKinds;
	}

	@Override
	public boolean isBreakpointValid(TraceBreakpoint breakpoint) {
		if (breakpoint.getName().endsWith("emu-" + breakpoint.getMinAddress())) {
			return false;
		}
		if (!breakpoint.getLifespan().contains(getSnap())) {
			return false;
		}
		return true;
	}

	protected CompletableFuture<Void> deleteBreakpointSpecAsync(TraceObjectBreakpointSpec spec) {
		MatchedMethod delBreak =
			matches.getBest("delBreakSpec", ActionName.DELETE, DelBreakMatcher.SPEC);
		if (delBreak == null) {
			return AsyncUtils.nil();
		}
		return delBreak.method
				.invokeAsync(Map.of(delBreak.params.get("specification").name(), spec))
				.toCompletableFuture()
				.thenApply(__ -> null);
	}

	protected CompletableFuture<Void> deleteBreakpointLocAsync(TraceObjectBreakpointLocation loc) {
		MatchedMethod delBreak =
			matches.getBest("delBreakLoc", ActionName.DELETE, DelBreakMatcher.ALL);
		if (delBreak == null) {
			return AsyncUtils.nil();
		}
		RemoteParameter paramLocation = delBreak.params.get("location");
		if (paramLocation != null) {
			return delBreak.method.invokeAsync(Map.of(paramLocation.name(), loc))
					.toCompletableFuture()
					.thenApply(__ -> null);
		}
		return deleteBreakpointSpecAsync(loc.getSpecification());
	}

	@Override
	public CompletableFuture<Void> deleteBreakpointAsync(TraceBreakpoint breakpoint) {
		if (breakpoint instanceof TraceObjectBreakpointLocation loc) {
			return deleteBreakpointLocAsync(loc);
		}
		if (breakpoint instanceof TraceObjectBreakpointSpec spec) {
			return deleteBreakpointSpecAsync(spec);
		}
		Msg.error(this, "Unrecognized TraceBreakpoint: " + breakpoint);
		return AsyncUtils.nil();
	}

	protected CompletableFuture<Void> toggleBreakpointSpecAsync(TraceObjectBreakpointSpec spec,
			boolean enabled) {
		MatchedMethod delBreak =
			matches.getBest("toggleBreakSpec", ActionName.TOGGLE, ToggleBreakMatcher.SPEC);
		if (delBreak == null) {
			return AsyncUtils.nil();
		}
		return delBreak.method
				.invokeAsync(Map.ofEntries(
					Map.entry(delBreak.params.get("specification").name(), spec),
					Map.entry(delBreak.params.get("enabled").name(), enabled)))
				.toCompletableFuture()
				.thenApply(__ -> null);
	}

	protected CompletableFuture<Void> toggleBreakpointLocAsync(TraceObjectBreakpointLocation loc,
			boolean enabled) {
		MatchedMethod delBreak =
			matches.getBest("toggleBreakLoc", ActionName.TOGGLE, ToggleBreakMatcher.ALL);
		if (delBreak == null) {
			return AsyncUtils.nil();
		}
		RemoteParameter paramLocation = delBreak.params.get("location");
		if (paramLocation != null) {
			return delBreak.method
					.invokeAsync(Map.ofEntries(
						Map.entry(paramLocation.name(), loc),
						Map.entry(delBreak.params.get("enabled").name(), enabled)))
					.toCompletableFuture()
					.thenApply(__ -> null);
		}
		return deleteBreakpointSpecAsync(loc.getSpecification());
	}

	@Override
	public CompletableFuture<Void> toggleBreakpointAsync(TraceBreakpoint breakpoint,
			boolean enabled) {
		if (breakpoint instanceof TraceObjectBreakpointLocation loc) {
			return toggleBreakpointLocAsync(loc, enabled);
		}
		if (breakpoint instanceof TraceObjectBreakpointSpec spec) {
			return toggleBreakpointSpecAsync(spec, enabled);
		}
		Msg.error(this, "Unrecognized TraceBreakpoint: " + breakpoint);
		return AsyncUtils.nil();
	}

	@Override
	public CompletableFuture<Void> disconnectAsync() {
		return CompletableFuture.runAsync(() -> {
			try {
				connection.close();
			}
			catch (IOException e) {
				ExceptionUtils.rethrow(e);
			}
		});
	}
}
