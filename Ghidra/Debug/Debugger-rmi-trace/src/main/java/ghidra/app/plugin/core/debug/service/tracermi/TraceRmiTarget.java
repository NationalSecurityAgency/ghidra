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
package ghidra.app.plugin.core.debug.service.tracermi;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.swing.Icon;

import org.apache.commons.lang3.exception.ExceptionUtils;

import docking.ActionContext;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.core.debug.gui.tracermi.RemoteMethodInvocationDialog;
import ghidra.app.plugin.core.debug.service.target.AbstractTarget;
import ghidra.app.services.DebuggerConsoleService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.async.AsyncFence;
import ghidra.async.AsyncUtils;
import ghidra.debug.api.ValStr;
import ghidra.debug.api.model.DebuggerObjectActionContext;
import ghidra.debug.api.model.DebuggerSingleObjectPathActionContext;
import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.debug.api.tracermi.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.*;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.iface.*;
import ghidra.trace.model.target.info.TraceObjectInterfaceUtils;
import ghidra.trace.model.target.path.*;
import ghidra.trace.model.target.path.PathFilter.Align;
import ghidra.trace.model.target.schema.*;
import ghidra.trace.model.target.schema.PrimitiveTraceObjectSchema.MinimalSchemaContext;
import ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName;
import ghidra.trace.model.thread.TraceProcess;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.TraceSchedule.ScheduleForm;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class TraceRmiTarget extends AbstractTarget {
	class TraceRmiActionEntry implements ActionEntry {
		private final RemoteMethod method;
		private final Map<String, Object> args;
		private final boolean requiresPrompt;
		private final long specificity;
		private final ParamAndObjectArg first;

		public TraceRmiActionEntry(RemoteMethod method, Map<String, Object> args) {
			this.method = method;
			this.args = args;

			this.requiresPrompt = args.values().contains(Missing.MISSING);
			this.specificity = computeSpecificity(method, args);
			this.first = getFirstObjectArgument(method, args);
		}

		@Override
		public String display() {
			return method.display();
		}

		@Override
		public ActionName name() {
			return method.action();
		}

		@Override
		public Icon icon() {
			return method.icon();
		}

		@Override
		public String details() {
			return method.description();
		}

		@Override
		public boolean requiresPrompt() {
			return requiresPrompt;
		}

		@Override
		public long specificity() {
			return specificity;
		}

		@Override
		public CompletableFuture<?> invokeAsyncWithoutTimeout(boolean prompt) {
			return invokeMethod(prompt, method, args);
		}

		@Override
		public boolean isEnabled() {
			if (first == null) {
				return true;
			}
			if (first.obj == null) {
				return false;
			}
			return name().enabler().isEnabled(first.obj, getSnap());
		}
	}

	private final TraceRmiConnection connection;
	private final Trace trace;

	private final Matches matches = new Matches();
	private final RequestCaches requestCaches = new DorkedRequestCaches();
	private final Set<TraceBreakpointKind> supportedBreakpointKinds;

	public TraceRmiTarget(PluginTool tool, TraceRmiConnection connection, Trace trace) {
		super(tool);
		this.connection = connection;
		this.trace = trace;
		this.supportedBreakpointKinds = computeSupportedBreakpointKinds();
	}

	@Override
	public String describe() {
		return "%s in %s at %s (rmi)".formatted(getTrace().getDomainFile().getName(),
			connection.getDescription(), connection.getRemoteAddress());
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

	protected ScheduleForm getSupportedTimeFormByMethod(TraceObject obj) {
		KeyPath path = obj.getCanonicalPath();
		MatchedMethod activate = matches.getBest(ActivateMatcher.class, path, ActionName.ACTIVATE,
			ActivateMatcher.makeBySpecificity(obj.getRoot().getSchema(), path));
		if (activate == null) {
			return null;
		}
		if (activate.params.get("time") != null) {
			return ScheduleForm.SNAP_ANY_STEPS_OPS;
		}
		if (activate.params.get("snap") != null) {
			return ScheduleForm.SNAP_ONLY;
		}
		return null;
	}

	protected ScheduleForm getSupportedTimeFormByAttribute(TraceObject obj, long snap) {
		TraceObject eventScope = obj.findSuitableInterface(TraceEventScope.class);
		if (eventScope == null) {
			return null;
		}
		TraceObjectValue timeSupportStr =
			eventScope.getAttribute(snap, TraceEventScope.KEY_TIME_SUPPORT);
		if (timeSupportStr == null) {
			return null;
		}
		return ScheduleForm.valueOf(timeSupportStr.castValue());
	}

	@Override
	public ScheduleForm getSupportedTimeForm(TraceObject obj, long snap) {
		ScheduleForm byMethod = getSupportedTimeFormByMethod(obj);
		if (byMethod == null) {
			return null;
		}
		ScheduleForm byAttr = getSupportedTimeFormByAttribute(obj, snap);
		if (byAttr == null) {
			return null;
		}
		return byMethod.intersect(byAttr);
	}

	@Override
	public TraceExecutionState getThreadExecutionState(TraceThread thread) {
		return thread.getObject().getExecutionState(getSnap());
	}

	@Override
	public TraceThread getThreadForSuccessor(KeyPath path) {
		TraceObject object = trace.getObjectManager().getObjectByCanonicalPath(path);
		if (object == null) {
			return null;
		}
		return object.queryCanonicalAncestorsInterface(TraceThread.class)
				.findFirst()
				.orElse(null);
	}

	@Override
	public TraceStackFrame getStackFrameForSuccessor(KeyPath path) {
		TraceObject object = trace.getObjectManager().getObjectByCanonicalPath(path);
		if (object == null) {
			return null;
		}
		return object.queryCanonicalAncestorsInterface(TraceStackFrame.class)
				.findFirst()
				.orElse(null);
	}

	protected TraceObject findObject(ActionContext context, ObjectArgumentPolicy policy) {
		if (policy.allowContextObject()) {
			if (context instanceof DebuggerObjectActionContext ctx) {
				List<TraceObjectValue> values = ctx.getObjectValues();
				if (values.size() == 1) {
					TraceObjectValue ov = values.get(0);
					if (ov.isObject()) {
						return ov.getChild();
					}
				}
			}
			else if (context instanceof DebuggerSingleObjectPathActionContext ctx) {
				TraceObject object =
					trace.getObjectManager().getObjectByCanonicalPath(ctx.getPath());
				if (object != null) {
					return object;
				}
				object = trace.getObjectManager()
						.getObjectsByPath(Lifespan.at(getSnap()), ctx.getPath())
						.findAny()
						.orElse(null);
				if (object != null) {
					return object;
				}
			}
		}
		if (policy.allowCoordsObject()) {
			DebuggerTraceManagerService traceManager =
				tool.getService(DebuggerTraceManagerService.class);
			if (traceManager == null) {
				return null;
			}
			return traceManager.getCurrentFor(trace).getObject();
		}
		return null;
	}

	/**
	 * "Find" a boolean value for the given context.
	 * 
	 * <p>
	 * At the moment, this is only used for toggle actions, where the "found" parameter is the
	 * opposite of the context object's current state. That object is presumed the object argument
	 * of the "toggle" method.
	 * 
	 * @param action the action name, so this is only applied to {@link ActionName#TOGGLE}
	 * @param context the context in which to find the object whose current state is to be
	 *            considered
	 * @param policy how object arguments can be found
	 * @return a value if found, null if not
	 */
	protected Boolean findBool(ActionName action, ActionContext context,
			ObjectArgumentPolicy policy) {
		if (!Objects.equals(action, ActionName.TOGGLE)) {
			return null;
		}
		TraceObject object = findObject(context, policy);
		if (object == null) {
			return null;
		}
		TraceObjectValue attrEnabled =
			object.getAttribute(getSnap(), TraceTogglable.KEY_ENABLED);
		boolean enabled = attrEnabled != null && attrEnabled.getValue() instanceof Boolean b && b;
		return !enabled;
	}

	protected Object findArgumentForSchema(ActionName action, ActionContext context,
			TraceObjectSchema schema, ObjectArgumentPolicy policy) {
		if (schema instanceof PrimitiveTraceObjectSchema prim) {
			return switch (prim) {
				case OBJECT -> findObject(context, policy);
				case ADDRESS -> findAddress(context);
				case RANGE -> findRange(context);
				case BOOL -> findBool(action, context, policy);
				default -> null;
			};
		}
		TraceObject object = findObject(context, policy);
		if (object == null) {
			return null;
		}
		if (policy.allowSuitableRelative()) {
			return object.findSuitableSchema(schema);
		}
		if (object.getSchema() == schema) {
			return object;
		}
		return null;
	}

	/**
	 * A singleton to indicate missing arguments
	 */
	public enum Missing {
		/** The argument requires a prompt */
		MISSING;
	}

	protected Object findArgument(ActionName action, RemoteParameter parameter,
			ActionContext context, ObjectArgumentPolicy policy) {
		SchemaName type = parameter.type();
		SchemaContext ctx = getSchemaContext();
		if (ctx == null) {
			Msg.trace(this, "No root schema, yet: " + trace);
			return null;
		}
		TraceObjectSchema schema = ctx.getSchemaOrNull(type);
		if (schema == null) {
			Msg.error(this, "Schema " + type + " not in trace! " + trace);
			return null;
		}
		Object arg = findArgumentForSchema(action, context, schema, policy);
		if (arg != null) {
			return arg;
		}
		if (!parameter.required()) {
			return parameter.getDefaultValue();
		}
		return Missing.MISSING;
	}

	protected Map<String, Object> collectArguments(RemoteMethod method, ActionContext context,
			ObjectArgumentPolicy policy) {
		Map<String, Object> args = new HashMap<>();
		for (RemoteParameter param : method.parameters().values()) {
			Object found = findArgument(method.action(), param, context, policy);
			if (found != null) {
				args.put(param.name(), found);
			}
		}
		return args;
	}

	/**
	 * Compute the specificity of the entry.
	 * 
	 * More specific is generally preferred. There are two sorts of specificity here. 1) The
	 * specificity of the methods formal parameters. A parameter having a non-primitive schema is
	 * more specific than one having an ANY or OBJECT schema. 2) The specificity of the objects
	 * selected as arguments. This is crudely computed as the length of the canonical path.
	 * 
	 * @param method the method
	 * @param args the arguments
	 * @return the specificity
	 */
	protected static long computeSpecificity(RemoteMethod method, Map<String, Object> args) {
		long score = 0;
		for (RemoteParameter param : method.parameters().values()) {
			score += switch (MinimalSchemaContext.INSTANCE.getSchemaOrNull(param.type())) {
				case PrimitiveTraceObjectSchema prim -> switch (prim) {
					case ANY -> 0; // Absolutely not specific
					case OBJECT -> 1; // well, it is better than ANY
					default -> 2; // real primitives
				};
				/**
				 * Because we're using the "minimal" schema, not the actual one, anything
				 * user-defined will be null.
				 */
				case null -> 100;
				default -> 100;
			};
		}
		score *= 1000;
		for (Object o : args.values()) {
			if (o instanceof TraceObject obj) {
				score += obj.getCanonicalPath().size();
			}
		}
		return score;
	}

	protected RemoteParameter getFirstObjectParameter(RemoteMethod method) {
		SchemaContext ctx = getSchemaContext();
		if (ctx == null) {
			return null;
		}
		return method.parameters()
				.values()
				.stream()
				.filter(
					p -> TraceObjectInterfaceUtils.isTraceObject(ctx.getSchema(p.type()).getType()))
				.findFirst()
				.orElse(null);
	}

	record ParamAndObjectArg(RemoteParameter param, TraceObject obj) {}

	protected ParamAndObjectArg getFirstObjectArgument(RemoteMethod method,
			Map<String, Object> args) {
		RemoteParameter firstParam = getFirstObjectParameter(method);
		if (firstParam == null) {
			return null;
		}
		Object firstArg = args.get(firstParam.name());
		if (firstArg == null || !(firstArg instanceof TraceObject obj)) {
			Msg.trace(this, "MISSING first argument for " + method + "(" + firstParam + ")");
			return new ParamAndObjectArg(firstParam, null);
		}
		return new ParamAndObjectArg(firstParam, obj);
	}

	private Map<String, Object> promptArgs(RemoteMethod method, Map<String, Object> defaults) {
		/**
		 * TODO: RemoteMethod parameter descriptions should also use ValStr. This map conversion
		 * stuff is getting onerous and hacky.
		 */
		Map<String, ValStr<?>> defs = ValStr.fromPlainMap(defaults);
		RemoteMethodInvocationDialog dialog = new RemoteMethodInvocationDialog(tool,
			getSchemaContext(), method.display(), method.okText(), method.icon());
		Map<String, ValStr<?>> args = dialog.promptArguments(method.parameters(), defs, defs);
		return args == null ? null : ValStr.toPlainMap(args);
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
			ObjectArgumentPolicy policy) {
		Map<String, Object> args = collectArguments(method, context, policy);
		return new TraceRmiActionEntry(method, args);
	}

	protected Map<String, ActionEntry> collectFromMethods(Collection<RemoteMethod> methods,
			ActionContext context, ObjectArgumentPolicy policy) {
		Map<String, ActionEntry> result = new HashMap<>();
		for (RemoteMethod m : methods) {
			ActionEntry entry = createEntry(m, context, policy);
			result.put(m.name(), entry);
		}
		return result;
	}

	protected boolean isAddressMethod(RemoteMethod method, SchemaContext ctx) {
		return method.parameters()
				.values()
				.stream()
				.filter(p -> {
					TraceObjectSchema schema = ctx.getSchemaOrNull(p.type());
					if (schema == null) {
						Msg.error(this,
							"Method " + method + " refers to invalid schema name: " + p.type());
						return false;
					}
					return schema.getType() == Address.class;
				})
				.count() == 1;
	}

	protected Map<String, ActionEntry> collectAddressActions(ProgramLocationActionContext context) {
		SchemaContext ctx = getSchemaContext();
		Map<String, ActionEntry> result = new HashMap<>();
		for (RemoteMethod m : connection.getMethods().all().values()) {
			if (!isAddressMethod(m, ctx)) {
				continue;
			}
			result.put(m.name(), createEntry(m, context, ObjectArgumentPolicy.CURRENT_AND_RELATED));
		}
		return result;
	}

	protected Map<String, ActionEntry> collectAllActions(ActionContext context,
			ObjectArgumentPolicy policy) {
		return collectFromMethods(connection.getMethods().all().values(), context, policy);
	}

	protected Map<String, ActionEntry> collectByName(ActionName name, ActionContext context,
			ObjectArgumentPolicy policy) {
		return collectFromMethods(connection.getMethods().getByAction(name), context, policy);
	}

	@Override
	public Map<String, ActionEntry> collectActions(ActionName name, ActionContext context,
			ObjectArgumentPolicy policy) {
		if (name == null) {
			if (context instanceof ProgramLocationActionContext ctx) {
				return collectAddressActions(ctx);
			}
			return collectAllActions(context, policy);
		}
		return collectByName(name, context, policy);
	}

	@Override
	public boolean isSupportsFocus() {
		TraceObjectSchema schema = trace.getObjectManager().getRootSchema();
		if (schema == null) {
			Msg.trace(this, "Checked for focus support before root schema is available");
			return false;
		}
		return schema
				.getInterfaces()
				.contains(TraceFocusScope.class) &&
			!connection.getMethods().getByAction(ActionName.ACTIVATE).isEmpty();
	}

	@Override
	public KeyPath getFocus() {
		TraceObjectValue focusVal = trace.getObjectManager()
				.getRootObject()
				.getAttribute(getSnap(), TraceFocusScope.KEY_FOCUS);
		if (focusVal == null || !focusVal.isObject()) {
			return null;
		}
		return focusVal.getChild().getCanonicalPath();
	}

	interface MethodMatcher {
		default MatchedMethod match(RemoteMethod method, TraceObjectSchema rootSchema,
				KeyPath path) {
			List<ParamSpec> spec = spec();
			if (spec.size() != method.parameters().size()) {
				return null;
			}
			Map<String, RemoteParameter> found = new HashMap<>();
			for (ParamSpec ps : spec) {
				RemoteParameter param = ps.find(method, rootSchema, path);
				if (param == null) {
					return null;
				}
				found.put(ps.name(), param);
			}
			return new MatchedMethod(method, Map.copyOf(found), score());
		}

		List<ParamSpec> spec();

		int score();

		static MatchedMethod matchPreferredForm(RemoteMethod method, TraceObjectSchema rootSchema,
				KeyPath path, List<? extends MethodMatcher> preferred) {
			return preferred.stream()
					.map(m -> m.match(method, rootSchema, path))
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
			TraceObjectSchema rootSchema, KeyPath path, Class<?> type) {
		SchemaContext ctx = rootSchema.getContext();
		TraceObjectSchema sch = ctx.getSchemaOrNull(param.type());
		if (sch == null) {
			throw new RuntimeException(
				"The parameter '%s' of method '%s' refers to a non-existent schema '%s'"
						.formatted(param.name(), method.name(), param.type()));
		}
		if (type == TraceObject.class) {
			// The method cannot impose any further restriction. It must accept any object.
			return sch == PrimitiveTraceObjectSchema.OBJECT;
		}
		else if (TraceObjectInterface.class.isAssignableFrom(type)) {
			if (path == null) {
				return sch.getInterfaces().contains(type);
			}
			KeyPath found =
				rootSchema.searchForSuitable(type.asSubclass(TraceObjectInterface.class), path);
			if (found == null) {
				return false;
			}
			return sch == rootSchema.getSuccessorSchema(path);
		}
		else {
			return sch.getType() == type;
		}
	}

	interface ParamSpec {
		String name();

		RemoteParameter find(RemoteMethod method, TraceObjectSchema rootSchema, KeyPath path);
	}

	record SchemaParamSpec(String name, SchemaName schema) implements ParamSpec {
		@Override
		public RemoteParameter find(RemoteMethod method, TraceObjectSchema rootSchema,
				KeyPath path) {
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
		public RemoteParameter find(RemoteMethod method, TraceObjectSchema rootSchema,
				KeyPath path) {
			List<RemoteParameter> withType = method.parameters()
					.values()
					.stream()
					.filter(p -> typeMatches(method, p, rootSchema, path, type))
					.toList();
			if (withType.size() != 1) {
				return null;
			}
			return withType.get(0);
		}
	}

	record NameParamSpec(String name, Class<?> type) implements ParamSpec {
		@Override
		public RemoteParameter find(RemoteMethod method, TraceObjectSchema rootSchema,
				KeyPath path) {
			RemoteParameter param = method.parameters().get(name);
			if (param != null && typeMatches(method, param, rootSchema, path, type)) {
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

		static List<ActivateMatcher> makeBySpecificity(TraceObjectSchema rootSchema,
				KeyPath path) {
			List<ActivateMatcher> result = new ArrayList<>();
			result.addAll(makeAllFor((path.size() + 1) * 3,
				new TypeParamSpec("focus", TraceObject.class)));
			List<TraceObjectSchema> schemas = rootSchema.getSuccessorSchemas(path);
			for (int i = path.size(); i > 0; i--) { // Inclusive on both ends
				result.addAll(
					makeAllFor(i * 3, new SchemaParamSpec("focus", schemas.get(i).getName())));
			}
			return matchers(result);
		}
	}

	record ExecuteMatcher(int score, List<ParamSpec> spec) implements MethodMatcher {
		static final ExecuteMatcher HAS_CMD_TOSTRING = new ExecuteMatcher(2, List.of(
			new TypeParamSpec("command", String.class),
			new TypeParamSpec("toString", Boolean.class)));
		static final List<ExecuteMatcher> ALL = matchers(HAS_CMD_TOSTRING);
	}

	record ReadMemMatcher(int score, List<ParamSpec> spec) implements MethodMatcher {
		static final ReadMemMatcher HAS_PROC_RANGE = new ReadMemMatcher(2, List.of(
			new TypeParamSpec("process", TraceProcess.class),
			new TypeParamSpec("range", AddressRange.class)));
		static final ReadMemMatcher HAS_RANGE = new ReadMemMatcher(1, List.of(
			new TypeParamSpec("range", AddressRange.class)));
		static final List<ReadMemMatcher> ALL = matchers(HAS_PROC_RANGE, HAS_RANGE);
	}

	record WriteMemMatcher(int score, List<ParamSpec> spec) implements MethodMatcher {
		static final WriteMemMatcher HAS_PROC_START_DATA = new WriteMemMatcher(2, List.of(
			new TypeParamSpec("process", TraceProcess.class),
			new TypeParamSpec("start", Address.class),
			new TypeParamSpec("data", byte[].class)));
		static final WriteMemMatcher HAS_START_DATA = new WriteMemMatcher(1, List.of(
			new TypeParamSpec("start", Address.class),
			new TypeParamSpec("data", byte[].class)));
		static final List<WriteMemMatcher> ALL = matchers(HAS_PROC_START_DATA, HAS_START_DATA);
	}

	record ReadRegsMatcher(int score, List<ParamSpec> spec) implements MethodMatcher {
		static final ReadRegsMatcher HAS_CONTAINER = new ReadRegsMatcher(3, List.of(
			new TypeParamSpec("container", TraceRegisterContainer.class)));
		static final ReadRegsMatcher HAS_REGISTER = new ReadRegsMatcher(1, List.of(
			new TypeParamSpec("register", TraceRegister.class)));
		static final List<ReadRegsMatcher> ALL = matchers(HAS_CONTAINER, HAS_REGISTER);
	}

	record WriteRegMatcher(int score, List<ParamSpec> spec) implements MethodMatcher {
		static final WriteRegMatcher HAS_FRAME_NAME_VALUE = new WriteRegMatcher(3, List.of(
			new TypeParamSpec("frame", TraceStackFrame.class),
			new TypeParamSpec("name", String.class),
			new TypeParamSpec("value", byte[].class)));
		static final WriteRegMatcher HAS_THREAD_NAME_VALUE = new WriteRegMatcher(2, List.of(
			new TypeParamSpec("thread", TraceThread.class),
			new TypeParamSpec("name", String.class),
			new TypeParamSpec("value", byte[].class)));
		static final WriteRegMatcher HAS_REG_VALUE = new WriteRegMatcher(1, List.of(
			new TypeParamSpec("register", TraceRegister.class),
			new TypeParamSpec("value", byte[].class)));
		static final List<WriteRegMatcher> ALL = matchers(HAS_FRAME_NAME_VALUE, HAS_REG_VALUE);
	}

	record BreakExecMatcher(int score, List<ParamSpec> spec) implements MethodMatcher {
		static final BreakExecMatcher HAS_PROC_ADDR_COND_CMDS = new BreakExecMatcher(8, List.of(
			new TypeParamSpec("process", TraceProcess.class),
			new TypeParamSpec("address", Address.class),
			new NameParamSpec("condition", String.class),
			new NameParamSpec("commands", String.class)));
		static final BreakExecMatcher HAS_PROC_ADDR_COND = new BreakExecMatcher(7, List.of(
			new TypeParamSpec("process", TraceProcess.class),
			new TypeParamSpec("address", Address.class),
			new NameParamSpec("condition", String.class)));
		static final BreakExecMatcher HAS_PROC_ADDR_CMDS = new BreakExecMatcher(6, List.of(
			new TypeParamSpec("process", TraceProcess.class),
			new TypeParamSpec("address", Address.class),
			new NameParamSpec("commands", String.class)));
		static final BreakExecMatcher HAS_PROC_ADDR = new BreakExecMatcher(5, List.of(
			new TypeParamSpec("process", TraceProcess.class),
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
			new TypeParamSpec("process", TraceProcess.class),
			new TypeParamSpec("range", AddressRange.class),
			new NameParamSpec("condition", String.class),
			new NameParamSpec("commands", String.class)));
		static final BreakAccMatcher HAS_PROC_RNG_COND = new BreakAccMatcher(7, List.of(
			new TypeParamSpec("process", TraceProcess.class),
			new TypeParamSpec("range", AddressRange.class),
			new NameParamSpec("condition", String.class)));
		static final BreakAccMatcher HAS_PROC_RNG_CMDS = new BreakAccMatcher(6, List.of(
			new TypeParamSpec("process", TraceProcess.class),
			new TypeParamSpec("range", AddressRange.class),
			new NameParamSpec("commands", String.class)));
		static final BreakAccMatcher HAS_PROC_RNG = new BreakAccMatcher(5, List.of(
			new TypeParamSpec("process", TraceProcess.class),
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
			new TypeParamSpec("location", TraceBreakpointLocation.class)));
		static final DelBreakMatcher HAS_SPEC = new DelBreakMatcher(1, List.of(
			new TypeParamSpec("specification", TraceBreakpointSpec.class)));
		static final List<DelBreakMatcher> ALL = matchers(HAS_LOC, HAS_SPEC);
		static final List<DelBreakMatcher> SPEC = matchers(HAS_SPEC);
	}

	record ToggleBreakMatcher(int score, List<ParamSpec> spec) implements MethodMatcher {
		static final ToggleBreakMatcher HAS_LOC = new ToggleBreakMatcher(2, List.of(
			new TypeParamSpec("location", TraceBreakpointLocation.class),
			new TypeParamSpec("enabled", Boolean.class)));
		static final ToggleBreakMatcher HAS_SPEC = new ToggleBreakMatcher(1, List.of(
			new TypeParamSpec("specification", TraceBreakpointSpec.class),
			new TypeParamSpec("enabled", Boolean.class)));
		static final List<ToggleBreakMatcher> ALL = matchers(HAS_LOC, HAS_SPEC);
		static final List<ToggleBreakMatcher> SPEC = matchers(HAS_SPEC);
	}

	record MatchKey(Class<? extends MethodMatcher> cls, ActionName action, TraceObjectSchema sch) {}

	protected class Matches {
		private final Map<MatchKey, MatchedMethod> map = new HashMap<>();

		public MatchKey makeKey(Class<? extends MethodMatcher> cls, ActionName action,
				KeyPath path) {
			TraceObjectSchema rootSchema = trace.getObjectManager().getRootSchema();
			if (rootSchema == null) {
				return null;
			}
			return new MatchKey(cls, action,
				path == null ? null : rootSchema.getSuccessorSchema(path));
		}

		public <T extends MethodMatcher> MatchedMethod getBest(Class<T> cls, KeyPath path,
				ActionName action, Supplier<List<T>> preferredSupplier) {
			return getBest(cls, path, action, preferredSupplier.get());
		}

		/**
		 * Search for the most preferred method for a given operation, with respect to a given path
		 * 
		 * <p>
		 * A given path should be given as a point of reference, usually the current object or the
		 * object from the UI action context. If given, parameters that require a certain
		 * {@link TraceObjectInterface} will seek a suitable schema from that path and require it.
		 * Otherwise, any parameter whose schema includes the interface will be accepted.
		 * 
		 * @param <T> the matcher class representing the desired operation
		 * @param cls the matcher class representing the desired operation
		 * @param path a path as a point of reference, or null for "any" point of reference.
		 * @param action the required action name for a matching method
		 * @param preferred the list of matchers (signatures) in preferred order
		 * @return the best method, or null
		 */
		public <T extends MethodMatcher> MatchedMethod getBest(Class<T> cls, KeyPath path,
				ActionName action, List<T> preferred) {
			MatchKey key = makeKey(cls, action, path);
			synchronized (map) {
				return map.computeIfAbsent(key, k -> chooseBest(action, path, preferred));
			}
		}

		private MatchedMethod chooseBest(ActionName name, KeyPath path,
				List<? extends MethodMatcher> preferred) {
			if (preferred.isEmpty()) {
				return null;
			}
			TraceObjectSchema rootSchema = trace.getObjectManager().getRootSchema();
			if (rootSchema == null) {
				return null;
			}
			MatchedMethod best = connection.getMethods()
					.getByAction(name)
					.stream()
					.map(m -> MethodMatcher.matchPreferredForm(m, rootSchema, path, preferred))
					.filter(f -> f != null)
					.max(MatchedMethod::compareTo)
					.orElse(null);
			if (best == null) {
				Msg.debug(this, "No suitable " + name + " method");
			}
			return best;
		}
	}

	interface RequestCaches {
		void invalidate();

		void invalidateMemory();

		CompletableFuture<Void> readBlock(Address min, RemoteMethod method,
				Map<String, Object> args);

		CompletableFuture<Void> readRegs(TraceObject obj, RemoteMethod method,
				Map<String, Object> args);
	}

	protected static class DefaultRequestCaches implements RequestCaches {
		final Map<TraceObject, CompletableFuture<Void>> readRegs = new HashMap<>();
		final Map<Address, CompletableFuture<Void>> readBlock = new HashMap<>();

		@Override
		public synchronized void invalidateMemory() {
			readBlock.clear();
		}

		@Override
		public synchronized void invalidate() {
			readRegs.clear();
			readBlock.clear();
		}

		@Override
		public synchronized CompletableFuture<Void> readRegs(TraceObject obj, RemoteMethod method,
				Map<String, Object> args) {
			return readRegs.computeIfAbsent(obj,
				o -> method.invokeAsync(args).toCompletableFuture().thenApply(__ -> null));
		}

		@Override
		public synchronized CompletableFuture<Void> readBlock(Address min, RemoteMethod method,
				Map<String, Object> args) {
			return readBlock.computeIfAbsent(min,
				m -> method.invokeAsync(args).toCompletableFuture().thenApply(__ -> null));
		}
	}

	protected static class DorkedRequestCaches implements RequestCaches {
		@Override
		public void invalidate() {
		}

		@Override
		public void invalidateMemory() {
		}

		@Override
		public CompletableFuture<Void> readBlock(Address min, RemoteMethod method,
				Map<String, Object> args) {
			return method.invokeAsync(args).toCompletableFuture().thenApply(__ -> null);
		}

		@Override
		public CompletableFuture<Void> readRegs(TraceObject obj, RemoteMethod method,
				Map<String, Object> args) {
			return method.invokeAsync(args).toCompletableFuture().thenApply(__ -> null);
		}
	}

	@Override
	public CompletableFuture<String> executeAsync(String command, boolean toString) {
		MatchedMethod execute =
			matches.getBest(ExecuteMatcher.class, null, ActionName.EXECUTE, ExecuteMatcher.ALL);
		if (execute == null) {
			return CompletableFuture.failedFuture(new NoSuchElementException());
		}
		Map<String, Object> args = new HashMap<>();
		args.put(execute.params.get("command").name(), command);
		args.put(execute.params.get("toString").name(), toString);
		return execute.method.invokeAsync(args).toCompletableFuture().thenApply(v -> (String) v);
	}

	@Override
	public CompletableFuture<Void> activateAsync(DebuggerCoordinates prev,
			DebuggerCoordinates coords) {
		boolean timeNeq = !Objects.equals(prev.getTime(), coords.getTime());
		if (timeNeq) {
			requestCaches.invalidate();
		}
		TraceObject object = coords.getObject();
		if (object == null) {
			return AsyncUtils.nil();
		}

		KeyPath path = object.getCanonicalPath();
		MatchedMethod activate = matches.getBest(ActivateMatcher.class, path, ActionName.ACTIVATE,
			ActivateMatcher.makeBySpecificity(object.getRoot().getSchema(), path));
		if (activate == null) {
			return AsyncUtils.nil();
		}

		Map<String, Object> args = new HashMap<>();
		RemoteParameter paramFocus = activate.params.get("focus");
		args.put(paramFocus.name(),
			object.findSuitableSchema(getSchemaContext().getSchema(paramFocus.type())));
		RemoteParameter paramTime = activate.params.get("time");
		if (paramTime != null && (paramTime.required() || timeNeq)) {
			args.put(paramTime.name(), coords.getTime().toString());
		}
		RemoteParameter paramSnap = activate.params.get("snap");
		if (paramSnap != null && (paramSnap.required() || timeNeq)) {
			args.put(paramSnap.name(), coords.getSnap());
		}
		return activate.method.invokeAsync(args).toCompletableFuture().thenApply(__ -> null);
	}

	@Override
	public CompletableFuture<Void> invalidateMemoryCachesAsync() {
		requestCaches.invalidateMemory();
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
		TraceObjectSchema rootSchema = trace.getObjectManager().getRootSchema();
		if (rootSchema == null) {
			return null;
		}
		return rootSchema.getContext();
	}

	protected TraceObject getProcessForSpace(AddressSpace space) {
		List<TraceProcess> processes = trace.getObjectManager()
				.queryAllInterface(Lifespan.at(getSnap()), TraceProcess.class)
				.toList();
		if (processes.size() == 1) {
			return processes.get(0).getObject();
		}
		if (processes.isEmpty()) {
			return null;
		}
		for (TraceMemoryRegion region : trace.getMemoryManager()
				.getRegionsIntersecting(Lifespan.at(getSnap()),
					new AddressRangeImpl(space.getMinAddress(), space.getMaxAddress()))) {
			TraceObject obj = region.getObject();
			return obj.findCanonicalAncestorsInterface(TraceProcess.class)
					.findFirst()
					.orElse(null);
		}
		return null;
	}

	@Override
	public CompletableFuture<Void> readMemoryAsync(AddressSetView set, TaskMonitor monitor) {
		/**
		 * I still separate into blocks, because I want user to be able to cancel. I don't intend to
		 * warn about the number of requests. They're delivered in serial, and there's a cancel
		 * button that works
		 */

		MatchedMethod readMem =
			matches.getBest(ReadMemMatcher.class, null, ActionName.READ_MEM, ReadMemMatcher.ALL);
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

		/**
		 * NOTE: Don't read in parallel, lest we overload the connection. This does queue them all
		 * up in a CF chain, though. Still, a request doesn't go out until the preceding one
		 * completes.
		 */
		return quantized.stream().flatMap(r -> {
			if (r.getAddressSpace().isRegisterSpace()) {
				Msg.warn(this, "Request to read registers via readMemory: " + r + ". Ignoring.");
				return Stream.of();
			}
			return new AddressRangeChunker(r, BLOCK_SIZE).stream();
		}).reduce(AsyncUtils.nil(), (f, blk) -> {
			if (monitor.isCancelled()) {
				return f;
			}
			final Map<String, Object> args;
			if (paramProcess != null) {
				TraceObject process = procsBySpace.computeIfAbsent(blk.getAddressSpace(),
					this::getProcessForSpace);
				if (process == null) {
					return f;
				}
				args = Map.ofEntries(
					Map.entry(paramProcess.name(), process),
					Map.entry(paramRange.name(), blk));
			}
			else {
				args = Map.ofEntries(
					Map.entry(paramRange.name(), blk));
			}

			return f.thenComposeAsync(__ -> {
				if (monitor.isCancelled()) {
					return AsyncUtils.nil();
				}
				monitor.incrementProgress(1);
				return requestCaches.readBlock(blk.getMinAddress(), readMem.method, args);
			}, AsyncUtils.FRAMEWORK_EXECUTOR).exceptionally(e -> {
				Msg.error(this, "Could not read " + blk + ": " + e);
				return null; // Continue looping on errors
			});
		}, (f1, f2) -> {
			throw new AssertionError("Should be sequential");
		});
	}

	@Override
	public CompletableFuture<Void> writeMemoryAsync(Address address, byte[] data) {
		MatchedMethod writeMem =
			matches.getBest(WriteMemMatcher.class, null, ActionName.WRITE_MEM, WriteMemMatcher.ALL);
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
			matches.getBest(ReadRegsMatcher.class, null, ActionName.REFRESH, ReadRegsMatcher.ALL);
		if (readRegs == null) {
			return AsyncUtils.nil();
		}
		TraceObject container = thread.getObject().findRegisterContainer(frame);
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
				.findSuccessorsInterface(Lifespan.at(getSnap()), TraceRegister.class, true)
				.filter(p -> keys.contains(p.getLastEntry().getEntryKey().toLowerCase()))
				.map(r -> r.getDestination(null))
				.collect(Collectors.toSet());
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

	protected TraceObjectValue tryRegister(TraceObject container, PathFilter filter, String name) {
		final PathFilter applied;
		if (filter.isNone()) {
			applied = PathMatcher.any(
				new PathPattern(KeyPath.ROOT.key(name)),
				new PathPattern(KeyPath.ROOT.key(name.toLowerCase())),
				new PathPattern(KeyPath.ROOT.key(name.toUpperCase())),
				new PathPattern(KeyPath.ROOT.index(name)),
				new PathPattern(KeyPath.ROOT.index(name.toLowerCase())),
				new PathPattern(KeyPath.ROOT.index(name.toUpperCase())));
		}
		else {
			applied = PathMatcher.any(
				filter.applyKeys(Align.RIGHT, name),
				filter.applyKeys(Align.RIGHT, name.toLowerCase()),
				filter.applyKeys(Align.RIGHT, name.toUpperCase()));
		}
		TraceObjectValPath regValPath =
			container.getSuccessors(Lifespan.at(getSnap()), applied).findFirst().orElse(null);

		if (regValPath == null) {
			Msg.error(this, "Cannot find register object/value for " + name + " in " + container);
			return null;
		}
		return regValPath.getLastEntry();
	}

	record FoundRegister(Register register, TraceObjectValue value) {
		String name() {
			return KeyPath.parseIfIndex(value.getEntryKey());
		}
	}

	protected FoundRegister findRegister(TraceObject container, PathFilter filter,
			Register register) {
		TraceObjectValue val;
		val = tryRegister(container, filter, register.getName());
		if (val != null) {
			return new FoundRegister(register, val);
		}
		/**
		 * When checking for register validity, we consider it valid if it or any of its parents are
		 * valid, or any alias thereof.
		 */
		for (String alias : register.getAliases()) {
			val = tryRegister(container, filter, alias);
			if (val != null) {
				return new FoundRegister(register, val);
			}
		}
		Register parent = register.getParentRegister();
		if (parent == null) {
			return null;
		}
		return findRegister(container, filter, parent);
	}

	protected FoundRegister findRegister(TraceThread thread, int frame, Register register) {
		TraceObject container = thread.getObject().findRegisterContainer(frame);
		if (container == null) {
			Msg.error(this, "No register container for thread=" + thread + ",frame=" + frame);
			return null;
		}
		PathFilter filter = container.getSchema().searchFor(TraceRegister.class, true);
		return findRegister(container, filter, register);
	}

	protected byte[] getBytes(RegisterValue rv) {
		return Utils.bigIntegerToBytes(rv.getUnsignedValue(), rv.getRegister().getMinimumByteSize(),
			true);
	}

	protected RegisterValue retrieveAndCombine(TracePlatform platform, TraceThread thread,
			int frameLevel, FoundRegister found, RegisterValue value) {
		TraceMemorySpace regSpace =
			thread.getTrace().getMemoryManager().getMemoryRegisterSpace(thread, frameLevel, false);
		if (regSpace == null) {
			return new RegisterValue(found.register, BigInteger.ZERO).combineValues(value);
		}
		return regSpace.getValue(platform, getSnap(), found.register).combineValues(value);
	}

	@Override
	public CompletableFuture<Void> writeRegisterAsync(TracePlatform platform, TraceThread thread,
			int frameLevel, RegisterValue value) {
		MatchedMethod writeReg =
			matches.getBest(WriteRegMatcher.class, null, ActionName.WRITE_REG, WriteRegMatcher.ALL);
		if (writeReg == null) {
			return AsyncUtils.nil();
		}
		FoundRegister found = findRegister(thread, frameLevel, value.getRegister());
		if (found == null) {
			Msg.warn(this, "Could not find register " + value.getRegister() + " in object model.");
		}
		else if (found.register != value.getRegister()) {
			value = retrieveAndCombine(platform, thread, frameLevel, found, value);
		}

		RemoteParameter paramThread = writeReg.params.get("thread");
		if (paramThread != null) {
			return writeReg.method.invokeAsync(Map.ofEntries(
				Map.entry(paramThread.name(), thread.getObject()),
				Map.entry(writeReg.params.get("name").name(), found.name()),
				Map.entry(writeReg.params.get("value").name(), getBytes(value))))
					.toCompletableFuture()
					.thenApply(__ -> null);
		}

		RemoteParameter paramFrame = writeReg.params.get("frame");
		if (paramFrame != null) {
			TraceStack stack = trace.getStackManager().getLatestStack(thread, getSnap());
			TraceStackFrame frame = stack.getFrame(getSnap(), frameLevel, false);
			return writeReg.method.invokeAsync(Map.ofEntries(
				Map.entry(paramFrame.name(), frame.getObject()),
				Map.entry(writeReg.params.get("name").name(), found.name()),
				Map.entry(writeReg.params.get("value").name(), getBytes(value))))
					.toCompletableFuture()
					.thenApply(__ -> null);
		}
		if (found == null || !found.value.isObject()) {
			return AsyncUtils.nil();
		}
		return writeReg.method.invokeAsync(Map.ofEntries(
			Map.entry(writeReg.params.get("register").name(), found.value.getChild()),
			Map.entry(writeReg.params.get("value").name(), getBytes(value))))
				.toCompletableFuture()
				.thenApply(__ -> null);
	}

	protected boolean isMemorySpaceValid(TracePlatform platform, AddressSpace space) {
		return platform.getAddressFactory().getAddressSpace(space.getSpaceID()) == space;
	}

	protected boolean isRegisterValid(TracePlatform platform, TraceThread thread, int frame,
			Address address, int length) {
		if (!isMemorySpaceValid(platform, address.getAddressSpace())) {
			return false;
		}
		Register register =
			platform.getLanguage().getRegister(address.getPhysicalAddress(), length);
		if (register == null) {
			return false;
		}
		// May be primitive or object
		FoundRegister found = findRegister(thread, frame, register);
		if (found == null) {
			return false;
		}
		return true;
	}

	@Override
	public boolean isVariableExists(TracePlatform platform, TraceThread thread, int frame,
			Address address, int length) {
		if (address.isMemoryAddress()) {
			return isMemorySpaceValid(platform, address.getAddressSpace());
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
			Object proc = findArgumentForSchema(null, null,
				getSchemaContext().getSchema(paramProc.type()),
				ObjectArgumentPolicy.CURRENT_AND_RELATED);
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
		MatchedMethod breakHwExec = matches.getBest(BreakExecMatcher.class, null,
			ActionName.BREAK_HW_EXECUTE, BreakExecMatcher.ALL);
		if (breakHwExec == null) {
			return AsyncUtils.nil();
		}
		return doPlaceExecBreakAsync(breakHwExec, address, condition, commands);
	}

	protected CompletableFuture<Void> placeSwExecBreakAsync(Address address, String condition,
			String commands) {
		MatchedMethod breakSwExec = matches.getBest(BreakExecMatcher.class, null,
			ActionName.BREAK_SW_EXECUTE, BreakExecMatcher.ALL);
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
		MatchedMethod breakRead = matches.getBest(BreakAccMatcher.class, null,
			ActionName.BREAK_READ, BreakAccMatcher.ALL);
		if (breakRead == null) {
			return AsyncUtils.nil();
		}
		return doPlaceAccBreakAsync(breakRead, range, condition, commands);
	}

	protected CompletableFuture<Void> placeWriteBreakAsync(AddressRange range, String condition,
			String commands) {
		MatchedMethod breakWrite = matches.getBest(BreakAccMatcher.class, null,
			ActionName.BREAK_WRITE, BreakAccMatcher.ALL);
		if (breakWrite == null) {
			return AsyncUtils.nil();
		}
		return doPlaceAccBreakAsync(breakWrite, range, condition, commands);
	}

	protected CompletableFuture<Void> placeAccessBreakAsync(AddressRange range, String condition,
			String commands) {
		MatchedMethod breakAccess = matches.getBest(BreakAccMatcher.class, null,
			ActionName.BREAK_ACCESS, BreakAccMatcher.ALL);
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
	public boolean isBreakpointValid(TraceBreakpointLocation breakpoint) {
		long snap = getSnap();
		if (breakpoint.getName(snap).endsWith("emu-" + breakpoint.getMinAddress(snap))) {
			return false;
		}
		if (!breakpoint.isValid(snap)) {
			return false;
		}
		return true;
	}

	protected CompletableFuture<Void> deleteBreakpointSpecAsync(TraceBreakpointSpec spec) {
		KeyPath path = spec.getObject().getCanonicalPath();
		MatchedMethod delBreak =
			matches.getBest(DelBreakMatcher.class, path, ActionName.DELETE, DelBreakMatcher.SPEC);
		if (delBreak == null) {
			return AsyncUtils.nil();
		}
		return delBreak.method
				.invokeAsync(Map.of(delBreak.params.get("specification").name(), spec.getObject()))
				.toCompletableFuture()
				.thenApply(__ -> null);
	}

	// TODO: Would this make sense for any debugger? To delete individual locations?
	protected CompletableFuture<Void> deleteBreakpointLocAsync(TraceBreakpointLocation loc) {
		KeyPath path = loc.getObject().getCanonicalPath();
		MatchedMethod delBreak =
			matches.getBest(DelBreakMatcher.class, path, ActionName.DELETE, DelBreakMatcher.ALL);
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
	public CompletableFuture<Void> deleteBreakpointAsync(TraceBreakpointCommon breakpoint) {
		if (breakpoint instanceof TraceBreakpointLocation loc) {
			return deleteBreakpointLocAsync(loc);
		}
		if (breakpoint instanceof TraceBreakpointSpec spec) {
			return deleteBreakpointSpecAsync(spec);
		}
		Msg.error(this, "Unrecognized TraceBreakpoint: " + breakpoint);
		return AsyncUtils.nil();
	}

	protected CompletableFuture<Void> toggleBreakpointSpecAsync(TraceBreakpointSpec spec,
			boolean enabled) {
		KeyPath path = spec.getObject().getCanonicalPath();
		MatchedMethod toggleBreak =
			matches.getBest(ToggleBreakMatcher.class, path, ActionName.TOGGLE,
				ToggleBreakMatcher.SPEC);
		if (toggleBreak == null) {
			return AsyncUtils.nil();
		}
		return toggleBreak.method
				.invokeAsync(Map.ofEntries(
					Map.entry(toggleBreak.params.get("specification").name(), spec.getObject()),
					Map.entry(toggleBreak.params.get("enabled").name(), enabled)))
				.toCompletableFuture()
				.thenApply(__ -> null);
	}

	protected CompletableFuture<Void> toggleBreakpointLocAsync(TraceBreakpointLocation loc,
			boolean enabled) {
		KeyPath path = loc.getObject().getCanonicalPath();
		MatchedMethod toggleBreak =
			matches.getBest(ToggleBreakMatcher.class, path, ActionName.TOGGLE,
				ToggleBreakMatcher.ALL);
		if (toggleBreak == null) {
			Msg.debug(this, "Falling back to toggle spec");
			return toggleBreakpointSpecAsync(loc.getSpecification(), enabled);
		}
		RemoteParameter paramLocation = toggleBreak.params.get("location");
		if (paramLocation != null) {
			return toggleBreak.method
					.invokeAsync(Map.ofEntries(
						Map.entry(paramLocation.name(), loc.getObject()),
						Map.entry(toggleBreak.params.get("enabled").name(), enabled)))
					.toCompletableFuture()
					.thenApply(__ -> null);
		}
		return toggleBreakpointSpecAsync(loc.getSpecification(), enabled);
	}

	@Override
	public CompletableFuture<Void> toggleBreakpointAsync(TraceBreakpointCommon breakpoint,
			boolean enabled) {
		if (breakpoint instanceof TraceBreakpointLocation loc) {
			return toggleBreakpointLocAsync(loc, enabled);
		}
		if (breakpoint instanceof TraceBreakpointSpec spec) {
			return toggleBreakpointSpecAsync(spec, enabled);
		}
		Msg.error(this, "Unrecognized TraceBreakpoint: " + breakpoint);
		return AsyncUtils.nil();
	}

	@Override
	public CompletableFuture<Void> forceTerminateAsync() {
		Map<String, ActionEntry> kills =
			collectByName(ActionName.KILL, null, ObjectArgumentPolicy.CURRENT_AND_RELATED);
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

	@Override
	public boolean isBusy() {
		return connection.isBusy(this);
	}
}
