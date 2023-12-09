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
import java.util.concurrent.CompletableFuture;
import java.util.function.*;
import java.util.stream.Collectors;

import org.apache.commons.lang3.exception.ExceptionUtils;

import docking.ActionContext;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.core.debug.gui.model.DebuggerObjectActionContext;
import ghidra.app.plugin.core.debug.gui.tracermi.RemoteMethodInvocationDialog;
import ghidra.app.plugin.core.debug.service.target.AbstractTarget;
import ghidra.app.services.DebuggerConsoleService;
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
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceObjectMemoryRegion;
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
	private final RequestCaches requestCaches = new RequestCaches();
	private final Set<TraceBreakpointKind> supportedBreakpointKinds;

	public TraceRmiTarget(PluginTool tool, TraceRmiConnection connection, Trace trace) {
		super(tool);
		this.connection = connection;
		this.trace = trace;
		this.supportedBreakpointKinds = computeSupportedBreakpointKinds();
	}

	@Override
	public boolean isValid() {
		return !connection.isClosed() && connection.isTarget(trace);
	}

	@Override
	public Trace getTrace() {
		return trace;
	}

	@Override
	public long getSnap() {
		try {
			return connection.getLastSnapshot(trace);
		}
		catch (NoSuchElementException e) {
			return 0;
		}
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

	protected TraceObject findObject(ActionContext context, boolean allowContextObject,
			boolean allowCoordsObject) {
		if (allowContextObject) {
			if (context instanceof DebuggerObjectActionContext ctx) {
				List<TraceObjectValue> values = ctx.getObjectValues();
				if (values.size() == 1) {
					TraceObjectValue ov = values.get(0);
					if (ov.isObject()) {
						return ov.getChild();
					}
				}
			}
		}
		if (allowCoordsObject) {
			DebuggerTraceManagerService traceManager =
				tool.getService(DebuggerTraceManagerService.class);
			if (traceManager == null) {
				return null;
			}
			return traceManager.getCurrentFor(trace).getObject();
		}
		return null;
	}

	protected Object findArgumentForSchema(ActionContext context, TargetObjectSchema schema,
			boolean allowContextObject, boolean allowCoordsObject, boolean allowSuitableObject) {
		if (schema instanceof EnumerableTargetObjectSchema prim) {
			return switch (prim) {
				case OBJECT -> findObject(context, allowContextObject, allowCoordsObject);
				case ADDRESS -> findAddress(context);
				case RANGE -> findRange(context);
				default -> null;
			};
		}
		TraceObject object = findObject(context, allowContextObject, allowCoordsObject);
		if (object == null) {
			return null;
		}
		if (allowSuitableObject) {
			return object.querySuitableSchema(schema);
		}
		if (object.getTargetSchema() == schema) {
			return object;
		}
		return null;
	}

	private enum Missing {
		MISSING; // The argument requires a prompt
	}

	protected Object findArgument(RemoteParameter parameter, ActionContext context,
			boolean allowContextObject, boolean allowCoordsObject, boolean allowSuitableObject) {
		SchemaName type = parameter.type();
		SchemaContext ctx = getSchemaContext();
		if (ctx == null) {
			Msg.trace(this, "No root schema, yet: " + trace);
			return null;
		}
		TargetObjectSchema schema = ctx.getSchema(type);
		if (schema == null) {
			Msg.error(this, "Schema " + type + " not in trace! " + trace);
			return null;
		}
		Object arg = findArgumentForSchema(context, schema, allowContextObject, allowCoordsObject,
			allowSuitableObject);
		if (arg != null) {
			return arg;
		}
		if (!parameter.required()) {
			return parameter.getDefaultValue();
		}
		return Missing.MISSING;
	}

	protected Map<String, Object> collectArguments(RemoteMethod method, ActionContext context,
			boolean allowContextObject, boolean allowCoordsObject, boolean allowSuitableObject) {
		Map<String, Object> args = new HashMap<>();
		for (RemoteParameter param : method.parameters().values()) {
			Object found = findArgument(param, context, allowContextObject, allowCoordsObject,
				allowSuitableObject);
			if (found != null) {
				args.put(param.name(), found);
			}
		}
		return args;
	}

	private TargetExecutionState getStateOf(TraceObject object) {
		try {
			return object.getExecutionState(getSnap());
		}
		catch (NoSuchElementException e) {
			return TargetExecutionState.TERMINATED;
		}
	}

	private boolean whenState(TraceObject object,
			Predicate<TargetExecutionState> predicate) {
		try {
			TargetExecutionState state = getStateOf(object);
			return state == null || predicate.test(state);
		}
		catch (Exception e) {
			Msg.error(this, "Could not get state: " + e);
			return false;
		}
	}

	protected BooleanSupplier chooseEnabler(RemoteMethod method, Map<String, Object> args) {
		ActionName name = method.action();
		SchemaContext ctx = getSchemaContext();
		if (ctx == null) {
			return () -> true;
		}
		RemoteParameter firstParam = method.parameters()
				.values()
				.stream()
				.filter(p -> TargetObject.class.isAssignableFrom(ctx.getSchema(p.type()).getType()))
				.findFirst()
				.orElse(null);
		if (firstParam == null) {
			return () -> true;
		}
		Object firstArg = args.get(firstParam.name());
		if (firstArg == null || firstArg == Missing.MISSING) {
			Msg.trace(this, "MISSING first argument for " + method + "(" + firstParam + ")");
			return () -> false;
		}
		TraceObject obj = (TraceObject) firstArg;
		if (ActionName.RESUME.equals(name) ||
			ActionName.STEP_BACK.equals(name) ||
			ActionName.STEP_EXT.equals(name) ||
			ActionName.STEP_INTO.equals(name) ||
			ActionName.STEP_OUT.equals(name) ||
			ActionName.STEP_OVER.equals(name) ||
			ActionName.STEP_SKIP.equals(name)) {
			return () -> whenState(obj, state -> state != null && state.isStopped());
		}
		else if (ActionName.INTERRUPT.equals(name)) {
			return () -> whenState(obj, state -> state == null || state.isRunning());
		}
		else if (ActionName.KILL.equals(name)) {
			return () -> whenState(obj, state -> state == null || state.isAlive());
		}
		return () -> true;
	}

	private Map<String, Object> promptArgs(RemoteMethod method, Map<String, Object> defaults) {
		SchemaContext ctx = getSchemaContext();
		RemoteMethodInvocationDialog dialog = new RemoteMethodInvocationDialog(tool,
			method.name(), method.name(), null);
		while (true) {
			for (RemoteParameter param : method.parameters().values()) {
				Object val = defaults.get(param.name());
				if (val != null) {
					Class<?> type = ctx.getSchema(param.type()).getType();
					dialog.setMemorizedArgument(param.name(), type.asSubclass(Object.class),
						val);
				}
			}
			Map<String, Object> args = dialog.promptArguments(ctx, method.parameters(), defaults);
			if (args == null) {
				// Cancelled
				return null;
			}
			return args;
		}
	}

	private CompletableFuture<?> invokeMethod(boolean prompt, RemoteMethod method,
			Map<String, Object> arguments) {
		Map<String, Object> chosenArgs;
		if (prompt) {
			chosenArgs = promptArgs(method, arguments);
		}
		else {
			chosenArgs = arguments;
		}
		return method.invokeAsync(chosenArgs).thenAccept(result -> {
			DebuggerConsoleService consoleService =
				tool.getService(DebuggerConsoleService.class);
			Class<?> retType = getSchemaContext().getSchema(method.retType()).getType();
			if (consoleService != null && retType != Void.class && retType != Object.class) {
				consoleService.log(null, method.name() + " returned " + result);
			}
		}).toCompletableFuture();
	}

	protected ActionEntry createEntry(RemoteMethod method, ActionContext context,
			boolean allowContextObject, boolean allowCoordsObject, boolean allowSuitableObject) {
		Map<String, Object> args = collectArguments(method, context, allowContextObject,
			allowCoordsObject, allowSuitableObject);
		boolean requiresPrompt = args.values().contains(Missing.MISSING);
		return new ActionEntry(method.name(), method.action(), method.description(), requiresPrompt,
			chooseEnabler(method, args), prompt -> invokeMethod(prompt, method, args));
	}

	protected Map<String, ActionEntry> collectFromMethods(Collection<RemoteMethod> methods,
			ActionContext context, boolean allowContextObject, boolean allowCoordsObject,
			boolean allowSuitableObject) {
		Map<String, ActionEntry> result = new HashMap<>();
		for (RemoteMethod m : methods) {
			result.put(m.name(), createEntry(m, context, allowContextObject, allowCoordsObject,
				allowSuitableObject));
		}
		return result;
	}

	protected boolean isAddressMethod(RemoteMethod method, SchemaContext ctx) {
		return method.parameters()
				.values()
				.stream()
				.filter(p -> {
					TargetObjectSchema schema = ctx.getSchemaOrNull(p.type());
					if (schema == null) {
						Msg.error(this,
							"Method " + method + " refers to invalid schema name: " + p.type());
						return false;
					}
					return schema.getType() == Address.class;
				})
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
			result.put(m.name(), createEntry(m, context, true, true, true));
		}
		return result;
	}

	@Override
	protected Map<String, ActionEntry> collectAllActions(ActionContext context) {
		return collectFromMethods(connection.getMethods().all().values(), context, true, false,
			false);
	}

	protected Map<String, ActionEntry> collectByName(ActionName name, ActionContext context) {
		return collectFromMethods(connection.getMethods().getByAction(name), context, false, true,
			true);
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
			Msg.trace(this, "Checked for focus support before root schema is available");
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

	protected static boolean typeMatches(RemoteMethod method, RemoteParameter param,
			SchemaContext ctx, Class<?> type) {
		TargetObjectSchema sch = ctx.getSchemaOrNull(param.type());
		if (sch == null) {
			throw new RuntimeException(
				"The parameter '%s' of method '%s' refers to a non-existent schema '%s'"
						.formatted(param.name(), method.name(), param.type()));
		}
		if (type == TargetObject.class) {
			// The method cannot impose any further restriction. It must accept any object.
			return sch == EnumerableTargetObjectSchema.OBJECT;
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

	record SchemaParamSpec(String name, SchemaName schema) implements ParamSpec {
		@Override
		public RemoteParameter find(RemoteMethod method, SchemaContext ctx) {
			List<RemoteParameter> withType = method.parameters()
					.values()
					.stream()
					.filter(p -> schema.equals(p.type()))
					.toList();
			if (withType.size() != 1) {
				return null;
			}
			return withType.get(0);
		}
	}

	record TypeParamSpec(String name, Class<?> type) implements ParamSpec {
		@Override
		public RemoteParameter find(RemoteMethod method, SchemaContext ctx) {
			List<RemoteParameter> withType = method.parameters()
					.values()
					.stream()
					.filter(p -> typeMatches(method, p, ctx, type))
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
			if (param != null && typeMatches(method, param, ctx, type)) {
				return param;
			}
			return null;
		}
	}

	protected static <T extends MethodMatcher> List<T> matchers(List<T> list) {
		List<T> result = new ArrayList<>(list);
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
		return List.copyOf(result);
	}

	@SafeVarargs
	protected static <T extends MethodMatcher> List<T> matchers(T... list) {
		return matchers(Arrays.asList(list));
	}

	record ActivateMatcher(int score, List<ParamSpec> spec) implements MethodMatcher {
		static List<ActivateMatcher> makeAllFor(int addScore, ParamSpec focusSpec) {
			ActivateMatcher hasFocusTime = new ActivateMatcher(addScore + 3, List.of(
				focusSpec,
				new TypeParamSpec("time", String.class)));
			ActivateMatcher hasFocusSnap = new ActivateMatcher(addScore + 2, List.of(
				focusSpec,
				new TypeParamSpec("snap", Long.class)));
			ActivateMatcher hasFocus = new ActivateMatcher(addScore + 1, List.of(
				focusSpec));
			return matchers(hasFocusTime, hasFocusSnap, hasFocus);
		}

		static List<ActivateMatcher> makeBySpecificity(TargetObjectSchema rootSchema,
				TraceObjectKeyPath path) {
			List<ActivateMatcher> result = new ArrayList<>();
			List<String> keyList = path.getKeyList();
			result.addAll(makeAllFor((keyList.size() + 1) * 3,
				new TypeParamSpec("focus", TargetObject.class)));
			List<TargetObjectSchema> schemas = rootSchema.getSuccessorSchemas(keyList);
			for (int i = keyList.size(); i > 0; i--) { // Inclusive on both ends
				result.addAll(
					makeAllFor(i * 3, new SchemaParamSpec("focus", schemas.get(i).getName())));
			}
			return matchers(result);
		}
	}

	record ReadMemMatcher(int score, List<ParamSpec> spec) implements MethodMatcher {
		static final ReadMemMatcher HAS_PROC_RANGE = new ReadMemMatcher(2, List.of(
			new TypeParamSpec("process", TargetProcess.class),
			new TypeParamSpec("range", AddressRange.class)));
		static final ReadMemMatcher HAS_RANGE = new ReadMemMatcher(1, List.of(
			new TypeParamSpec("range", AddressRange.class)));
		static final List<ReadMemMatcher> ALL = matchers(HAS_PROC_RANGE, HAS_RANGE);
	}

	record WriteMemMatcher(int score, List<ParamSpec> spec) implements MethodMatcher {
		static final WriteMemMatcher HAS_PROC_START_DATA = new WriteMemMatcher(2, List.of(
			new TypeParamSpec("process", TargetProcess.class),
			new TypeParamSpec("start", Address.class),
			new TypeParamSpec("data", byte[].class)));
		static final WriteMemMatcher HAS_START_DATA = new WriteMemMatcher(1, List.of(
			new TypeParamSpec("start", Address.class),
			new TypeParamSpec("data", byte[].class)));
		static final List<WriteMemMatcher> ALL = matchers(HAS_PROC_START_DATA, HAS_START_DATA);
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
		static final WriteRegMatcher HAS_FRAME_NAME_VALUE = new WriteRegMatcher(3, List.of(
			new TypeParamSpec("frame", TargetStackFrame.class),
			new TypeParamSpec("name", String.class),
			new TypeParamSpec("value", byte[].class)));
		static final WriteRegMatcher HAS_THREAD_NAME_VALUE = new WriteRegMatcher(2, List.of(
			new TypeParamSpec("thread", TargetThread.class),
			new TypeParamSpec("name", String.class),
			new TypeParamSpec("value", byte[].class)));
		static final WriteRegMatcher HAS_REG_VALUE = new WriteRegMatcher(1, List.of(
			new TypeParamSpec("register", TargetRegister.class),
			new TypeParamSpec("value", byte[].class)));
		static final List<WriteRegMatcher> ALL = matchers(HAS_FRAME_NAME_VALUE, HAS_REG_VALUE);
	}

	record BreakExecMatcher(int score, List<ParamSpec> spec) implements MethodMatcher {
		static final BreakExecMatcher HAS_PROC_ADDR_COND_CMDS = new BreakExecMatcher(8, List.of(
			new TypeParamSpec("process", TargetProcess.class),
			new TypeParamSpec("address", Address.class),
			new NameParamSpec("condition", String.class),
			new NameParamSpec("commands", String.class)));
		static final BreakExecMatcher HAS_PROC_ADDR_COND = new BreakExecMatcher(7, List.of(
			new TypeParamSpec("process", TargetProcess.class),
			new TypeParamSpec("address", Address.class),
			new NameParamSpec("condition", String.class)));
		static final BreakExecMatcher HAS_PROC_ADDR_CMDS = new BreakExecMatcher(6, List.of(
			new TypeParamSpec("process", TargetProcess.class),
			new TypeParamSpec("address", Address.class),
			new NameParamSpec("commands", String.class)));
		static final BreakExecMatcher HAS_PROC_ADDR = new BreakExecMatcher(5, List.of(
			new TypeParamSpec("process", TargetProcess.class),
			new TypeParamSpec("address", Address.class)));
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
			matchers(HAS_PROC_ADDR_COND_CMDS, HAS_PROC_ADDR_COND, HAS_PROC_ADDR_CMDS, HAS_PROC_ADDR,
				HAS_ADDR_COND_CMDS, HAS_ADDR_COND, HAS_ADDR_CMDS, HAS_ADDR);
	}

	// TODO: Probably need a better way to deal with optional requirements
	record BreakAccMatcher(int score, List<ParamSpec> spec) implements MethodMatcher {
		static final BreakAccMatcher HAS_PROC_RNG_COND_CMDS = new BreakAccMatcher(8, List.of(
			new TypeParamSpec("process", TargetProcess.class),
			new TypeParamSpec("range", AddressRange.class),
			new NameParamSpec("condition", String.class),
			new NameParamSpec("commands", String.class)));
		static final BreakAccMatcher HAS_PROC_RNG_COND = new BreakAccMatcher(7, List.of(
			new TypeParamSpec("process", TargetProcess.class),
			new TypeParamSpec("range", AddressRange.class),
			new NameParamSpec("condition", String.class)));
		static final BreakAccMatcher HAS_PROC_RNG_CMDS = new BreakAccMatcher(6, List.of(
			new TypeParamSpec("process", TargetProcess.class),
			new TypeParamSpec("range", AddressRange.class),
			new NameParamSpec("commands", String.class)));
		static final BreakAccMatcher HAS_PROC_RNG = new BreakAccMatcher(5, List.of(
			new TypeParamSpec("process", TargetProcess.class),
			new TypeParamSpec("range", AddressRange.class)));
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
			matchers(HAS_PROC_RNG_COND_CMDS, HAS_PROC_RNG_COND, HAS_PROC_RNG_CMDS, HAS_PROC_RNG,
				HAS_RNG_COND_CMDS, HAS_RNG_COND, HAS_RNG_CMDS, HAS_RNG);
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
				Supplier<List<? extends MethodMatcher>> preferredSupplier) {
			return map.computeIfAbsent(name, n -> chooseBest(action, preferredSupplier.get()));
		}

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
				Msg.debug(this, "No suitable " + name + " method");
			}
			return best;
		}
	}

	protected static class RequestCaches {
		final Map<TraceObject, CompletableFuture<Void>> readRegs = new HashMap<>();
		final Map<Address, CompletableFuture<Void>> readBlock = new HashMap<>();

		public synchronized void invalidate() {
			readRegs.clear();
			readBlock.clear();
		}

		public synchronized CompletableFuture<Void> readRegs(TraceObject obj, RemoteMethod method,
				Map<String, Object> args) {
			return readRegs.computeIfAbsent(obj,
				o -> method.invokeAsync(args).toCompletableFuture().thenApply(__ -> null));
		}

		public synchronized CompletableFuture<Void> readBlock(Address min, RemoteMethod method,
				Map<String, Object> args) {
			return readBlock.computeIfAbsent(min,
				m -> method.invokeAsync(args).toCompletableFuture().thenApply(__ -> null));
		}
	}

	@Override
	public CompletableFuture<Void> activateAsync(DebuggerCoordinates prev,
			DebuggerCoordinates coords) {
		if (prev.getSnap() != coords.getSnap()) {
			requestCaches.invalidate();
		}
		TraceObject object = coords.getObject();
		if (object == null) {
			return AsyncUtils.nil();
		}

		SchemaName name = object.getTargetSchema().getName();
		MatchedMethod activate = matches.getBest("activate_" + name, ActionName.ACTIVATE,
			() -> ActivateMatcher.makeBySpecificity(trace.getObjectManager().getRootSchema(),
				object.getCanonicalPath()));
		if (activate == null) {
			return AsyncUtils.nil();
		}

		Map<String, Object> args = new HashMap<>();
		RemoteParameter paramFocus = activate.params.get("focus");
		args.put(paramFocus.name(),
			object.querySuitableSchema(getSchemaContext().getSchema(paramFocus.type())));
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
		TargetObjectSchema rootSchema = trace.getObjectManager().getRootSchema();
		if (rootSchema == null) {
			return null;
		}
		return rootSchema.getContext();
	}

	protected TraceObject getProcessForSpace(AddressSpace space) {
		for (TraceObjectValue objVal : trace.getObjectManager()
				.getValuesIntersecting(
					Lifespan.at(getSnap()),
					new AddressRangeImpl(space.getMinAddress(), space.getMaxAddress()),
					TargetMemoryRegion.RANGE_ATTRIBUTE_NAME)) {
			TraceObject obj = objVal.getParent();
			if (!obj.getInterfaces().contains(TraceObjectMemoryRegion.class)) {
				continue;
			}
			return obj.queryCanonicalAncestorsTargetInterface(TargetProcess.class)
					.findFirst()
					.orElse(null);
		}
		return null;
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
		RemoteParameter paramProcess = readMem.params.get("process");

		final Map<AddressSpace, TraceObject> procsBySpace;
		if (paramProcess != null) {
			procsBySpace = new HashMap<>();
		}
		else {
			procsBySpace = null;
		}

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
			if (r.getAddressSpace().isRegisterSpace()) {
				Msg.warn(this, "Request to read registers via readMemory: " + r + ". Ignoring.");
				loop.repeatWhile(!monitor.isCancelled());
				return;
			}
			AsyncUtils.each(TypeSpec.VOID, blocks.iterator(), (blk, inner) -> {
				monitor.incrementProgress(1);
				final Map<String, Object> args;
				if (paramProcess != null) {
					TraceObject process = procsBySpace.computeIfAbsent(blk.getAddressSpace(),
						this::getProcessForSpace);
					if (process == null) {
						Msg.warn(this, "Cannot find process containing " + blk.getMinAddress());
						inner.repeatWhile(!monitor.isCancelled());
						return;
					}
					args = Map.ofEntries(
						Map.entry(paramProcess.name(), process),
						Map.entry(paramRange.name(), blk));
				}
				else {
					args = Map.ofEntries(
						Map.entry(paramRange.name(), blk));
				}
				CompletableFuture<Void> future =
					requestCaches.readBlock(blk.getMinAddress(), readMem.method, args);
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
		RemoteParameter paramProcess = writeMem.params.get("process");
		if (paramProcess != null) {
			TraceObject process = getProcessForSpace(address.getAddressSpace());
			if (process == null) {
				throw new IllegalStateException("Cannot find process containing " + address);
			}
			args.put(paramProcess.name(), process);
		}
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
		if (container == null) {
			Msg.error(this,
				"Cannot find register container for thread,frame: " + thread + "," + frame);
			return AsyncUtils.nil();
		}
		RemoteParameter paramContainer = readRegs.params.get("container");
		if (paramContainer != null) {
			return requestCaches.readRegs(container, readRegs.method, Map.of(
				paramContainer.name(), container));
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
				fence.include(requestCaches.readRegs(b, readRegs.method, Map.of(
					paramBank.name(), b)));
			});
			return fence.ready();
		}
		RemoteParameter paramRegister = readRegs.params.get("register");
		if (paramRegister != null) {
			AsyncFence fence = new AsyncFence();
			regs.stream().forEach(r -> {
				fence.include(requestCaches.readRegs(r, readRegs.method, Map.of(
					paramRegister.name(), r)));
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
			int frameLevel, RegisterValue value) {
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

		RemoteParameter paramThread = writeReg.params.get("thread");
		if (paramThread != null) {
			return writeReg.method.invokeAsync(Map.ofEntries(
				Map.entry(paramThread.name(), tot.getObject()),
				Map.entry(writeReg.params.get("name").name(), regName),
				Map.entry(writeReg.params.get("value").name(), data)))
					.toCompletableFuture()
					.thenApply(__ -> null);
		}

		RemoteParameter paramFrame = writeReg.params.get("frame");
		if (paramFrame != null) {
			TraceStack stack = trace.getStackManager().getLatestStack(thread, getSnap());
			TraceStackFrame frame = stack.getFrame(frameLevel, false);
			if (!(frame instanceof TraceObjectStackFrame tof)) {
				Msg.error(this, "Non-object trace with TraceRmi!");
				return AsyncUtils.nil();
			}
			return writeReg.method.invokeAsync(Map.ofEntries(
				Map.entry(paramFrame.name(), tof.getObject()),
				Map.entry(writeReg.params.get("name").name(), regName),
				Map.entry(writeReg.params.get("value").name(), data)))
					.toCompletableFuture()
					.thenApply(__ -> null);
		}
		TraceObject regObj = findRegisterObject(tot, frameLevel, regName);
		if (regObj == null) {
			return AsyncUtils.nil();
		}
		return writeReg.method.invokeAsync(Map.ofEntries(
			Map.entry(writeReg.params.get("frame").name(), regObj),
			Map.entry(writeReg.params.get("value").name(), data)))
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
		RemoteParameter paramProc = brk.params.get("process");
		if (paramProc != null) {
			Object proc =
				findArgumentForSchema(null, getSchemaContext().getSchema(paramProc.type()), true,
					true, true);
			if (proc == null) {
				Msg.error(this, "Cannot find required process argument for " + brk.method);
			}
			else {
				args.put(paramProc.name(), proc);
			}
		}
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
		if (copyKinds.equals(TraceBreakpointKindSet.HW_EXECUTE)) {
			return placeHwExecBreakAsync(expectSingleAddr(range, TraceBreakpointKind.HW_EXECUTE),
				condition, commands);
		}
		if (copyKinds.equals(TraceBreakpointKindSet.SW_EXECUTE)) {
			return placeSwExecBreakAsync(expectSingleAddr(range, TraceBreakpointKind.SW_EXECUTE),
				condition, commands);
		}
		if (copyKinds.equals(TraceBreakpointKindSet.READ)) {
			return placeReadBreakAsync(range, condition, commands);
		}
		if (copyKinds.equals(TraceBreakpointKindSet.WRITE)) {
			return placeWriteBreakAsync(range, condition, commands);
		}
		if (copyKinds.equals(TraceBreakpointKindSet.ACCESS)) {
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
				.invokeAsync(Map.of(delBreak.params.get("specification").name(), spec.getObject()))
				.toCompletableFuture()
				.thenApply(__ -> null);
	}

	// TODO: Would this make sense for any debugger? To delete individual locations?
	protected CompletableFuture<Void> deleteBreakpointLocAsync(TraceObjectBreakpointLocation loc) {
		MatchedMethod delBreak =
			matches.getBest("delBreakLoc", ActionName.DELETE, DelBreakMatcher.ALL);
		if (delBreak == null) {
			Msg.debug(this, "Falling back to delete spec");
			return deleteBreakpointSpecAsync(loc.getSpecification());
		}
		RemoteParameter paramLocation = delBreak.params.get("location");
		if (paramLocation != null) {
			return delBreak.method.invokeAsync(Map.of(paramLocation.name(), loc.getObject()))
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
					Map.entry(delBreak.params.get("specification").name(), spec.getObject()),
					Map.entry(delBreak.params.get("enabled").name(), enabled)))
				.toCompletableFuture()
				.thenApply(__ -> null);
	}

	protected CompletableFuture<Void> toggleBreakpointLocAsync(TraceObjectBreakpointLocation loc,
			boolean enabled) {
		MatchedMethod delBreak =
			matches.getBest("toggleBreakLoc", ActionName.TOGGLE, ToggleBreakMatcher.ALL);
		if (delBreak == null) {
			Msg.debug(this, "Falling back to toggle spec");
			return toggleBreakpointSpecAsync(loc.getSpecification(), enabled);
		}
		RemoteParameter paramLocation = delBreak.params.get("location");
		if (paramLocation != null) {
			return delBreak.method
					.invokeAsync(Map.ofEntries(
						Map.entry(paramLocation.name(), loc.getObject()),
						Map.entry(delBreak.params.get("enabled").name(), enabled)))
					.toCompletableFuture()
					.thenApply(__ -> null);
		}
		return toggleBreakpointSpecAsync(loc.getSpecification(), enabled);
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
	public CompletableFuture<Void> forceTerminateAsync() {
		Map<String, ActionEntry> kills = collectKillActions(null);
		for (ActionEntry kill : kills.values()) {
			if (kill.requiresPrompt()) {
				continue;
			}
			return kill.invokeAsync(false).handle((v, e) -> {
				connection.forceCloseTrace(trace);
				return null;
			});
		}
		Msg.warn(this, "Cannot find way to gracefully kill. Forcing close regardless.");
		connection.forceCloseTrace(trace);
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
