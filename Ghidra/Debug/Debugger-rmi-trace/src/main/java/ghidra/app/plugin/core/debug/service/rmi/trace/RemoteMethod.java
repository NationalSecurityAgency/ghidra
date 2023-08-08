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

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.Function;

import ghidra.async.AsyncUtils;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;

/**
 * A remote method registered by the back-end debugger.
 * 
 * <p>
 * Remote methods must describe the parameters names and types at a minimum. They should also
 * provide a display name and description for the method itself and each of its parameters. These
 * methods should not return a result. Instead, any "result" should be recorded into a trace. The
 * invocation can result in an error, which is communicated by an exception that can carry only a
 * message string. Choice few methods should return a result, for example, the {@code execute}
 * method with output capture. That output generally does not belong in a trace, so the only way to
 * communicate it back to the front end is to return it.
 */
public interface RemoteMethod {

	/**
	 * A "hint" for how to map the method to a common action.
	 * 
	 * <p>
	 * Many common commands/actions have varying names across different back-end debuggers. We'd
	 * like to present common idioms for these common actions, but allow them to keep the names used
	 * by the back-end, because those names are probably better known to users of that back-end than
	 * Ghidra's action names are known. The action hints will affect the icon and placement of the
	 * action in the UI, but the display name will still reflect the name given by the back-end.
	 * Note that the "stock" action names are not a fixed enumeration. These are just the ones that
	 * might get special treatment from Ghidra. All methods should appear somewhere (at least, e.g.,
	 * in context menus for applicable objects), even if the action name is unspecified or does not
	 * match a stock name. This list may change over time, but that shouldn't matter much. Each
	 * back-end should make its best effort to match its methods to these stock actions where
	 * applicable, but ultimately, it is up to the UI to decide what is presented where.
	 */
	public record Action(String name) {
		public static final Action REFRESH = new Action("refresh");
		public static final Action ACTIVATE = new Action("activate");
		/**
		 * A weaker form of activate.
		 * 
		 * <p>
		 * The user has expressed interest in an object, but has not activated it yet. This is often
		 * used to communicate selection (i.e., highlight) of the object. Whereas, double-clicking
		 * or pressing enter would more likely invoke 'activate.'
		 */
		public static final Action FOCUS = new Action("focus");
		public static final Action TOGGLE = new Action("toggle");
		public static final Action DELETE = new Action("delete");

		/**
		 * Forms: (cmd:STRING):STRING
		 * 
		 * Optional arguments: capture:BOOL
		 */
		public static final Action EXECUTE = new Action("execute");

		/**
		 * Forms: (spec:STRING)
		 */
		public static final Action CONNECT = new Action("connect");

		/**
		 * Forms: (target:Attachable), (pid:INT), (spec:STRING)
		 */
		public static final Action ATTACH = new Action("attach");
		public static final Action DETACH = new Action("detach");

		/**
		 * Forms: (command_line:STRING), (file:STRING,args:STRING), (file:STRING,args:STRING_ARRAY),
		 * (ANY*)
		 */
		public static final Action LAUNCH = new Action("launch");
		public static final Action KILL = new Action("kill");

		public static final Action RESUME = new Action("resume");
		public static final Action INTERRUPT = new Action("interrupt");

		/**
		 * All of these will show in the "step" portion of the control toolbar, if present. The
		 * difference in each "step_x" is minor. The icon will indicate which form, and the
		 * positions will be shifted so they appear in a consistent order. The display name is
		 * determined by the method name, not the action name. For stepping actions that don't fit
		 * the standards, use {@link #STEP_EXT}. There should be at most one of each standard
		 * applicable for any given context. (Multiple will appear, but may confuse the user.) You
		 * can have as many extended step actions as you like. They will be ordered
		 * lexicographically by name.
		 */
		public static final Action STEP_INTO = new Action("step_into");
		public static final Action STEP_OVER = new Action("step_over");
		public static final Action STEP_OUT = new Action("step_out");
		/**
		 * Skip is not typically available, except in emulators. If the back-end debugger does not
		 * have a command for this action out-of-the-box, we do not recommend trying to implement it
		 * yourself. The purpose of these actions just to expose/map each command to the UI, not to
		 * invent new features for the back-end debugger.
		 */
		public static final Action STEP_SKIP = new Action("step_skip");
		/**
		 * Step back is not typically available, except in emulators and timeless (or time-travel)
		 * debuggers.
		 */
		public static final Action STEP_BACK = new Action("step_back");
		/**
		 * The action for steps that don't fit one of the common stepping actions.
		 */
		public static final Action STEP_EXT = new Action("step_ext");

		/**
		 * Forms: (addr:ADDRESS), R/W(rng:RANGE), set(expr:STRING)
		 * 
		 * Optional arguments: condition:STRING, commands:STRING
		 */
		public static final Action BREAK_SW_EXECUTE = new Action("break_sw_execute");
		public static final Action BREAK_HW_EXECUTE = new Action("break_hw_execute");
		public static final Action BREAK_READ = new Action("break_read");
		public static final Action BREAK_WRITE = new Action("break_write");
		public static final Action BREAK_ACCESS = new Action("break_access");
		public static final Action BREAK_EXT = new Action("break_ext");

		/**
		 * Forms: (rng:RANGE)
		 */
		public static final Action READ_MEM = new Action("read_mem");
		/**
		 * Forms: (addr:ADDRESS,data:BYTES)
		 */
		public static final Action WRITE_MEM = new Action("write_mem");

		// NOTE: no read_reg. Use refresh(RegContainer), refresh(RegGroup), refresh(Register)
		/**
		 * Forms: (frame:Frame,name:STRING,value:BYTES), (register:Register,value:BYTES)
		 */
		public static final Action WRITE_REG = new Action("write_reg");
	}

	/**
	 * The name of the method.
	 * 
	 * @return the name
	 */
	String name();

	/**
	 * A string that hints at the UI action this method achieves.
	 * 
	 * @return the action
	 */
	Action action();

	/**
	 * A description of the method.
	 * 
	 * <p>
	 * This is the text for tooltips or other information presented by actions whose purpose is to
	 * invoke this method. If the back-end command name is well known to its users, this text should
	 * include that name.
	 * 
	 * @return the description
	 */
	String description();

	/**
	 * The methods parameters.
	 * 
	 * <p>
	 * Parameters are all keyword-style parameters. This returns a map of names to parameter
	 * descriptions.
	 * 
	 * @return the parameter map
	 */
	Map<String, RemoteParameter> parameters();

	/**
	 * Get the schema for the return type.
	 * 
	 * <b>NOTE:</b> Most methods should return void, i.e., either they succeed, or they throw/raise
	 * an error message. One notable exception is "execute," which may return the console output
	 * from executing a command. In most cases, the method should only cause an update to the trace
	 * database. That effect is its result.
	 * 
	 * @return the schema name for the method's return type.
	 */
	SchemaName retType();

	/**
	 * Check the type of an argument.
	 * 
	 * <p>
	 * This is a hack, because {@link TargetObjectSchema} expects {@link TargetObject}, or a
	 * primitive. We instead need {@link TraceObject}. I'd add the method to the schema, except that
	 * trace stuff is not in its dependencies.
	 * 
	 * @param name the name of the parameter
	 * @param sch the type of the parameter
	 * @param arg the argument
	 */
	static void checkType(String name, TargetObjectSchema sch, Object arg) {
		if (sch.getType() != TargetObject.class) {
			if (sch.getType().isInstance(arg)) {
				return;
			}
		}
		else if (arg instanceof TraceObject obj) {
			if (sch.equals(obj.getTargetSchema())) {
				return;
			}
		}
		throw new IllegalArgumentException(
			"For parameter %s: argument %s is not a %s".formatted(name, arg, sch));
	}

	/**
	 * Validate the given argument.
	 * 
	 * <p>
	 * This method is for checking parameter sanity before they are marshalled to the back-end. This
	 * is called automatically during invocation. Clients can use this method to pre-test or
	 * validate in the UI, when invocation is not yet desired.
	 * 
	 * @param arguments the arguments
	 * @return the trace if any object arguments were given, or null
	 * @throws IllegalArgumentException if the arguments are not valid
	 */
	default Trace validate(Map<String, Object> arguments) {
		Trace trace = null;
		SchemaContext ctx = EnumerableTargetObjectSchema.MinimalSchemaContext.INSTANCE;
		for (Map.Entry<String, RemoteParameter> ent : parameters().entrySet()) {
			if (!arguments.containsKey(ent.getKey())) {
				if (ent.getValue().required()) {
					throw new IllegalArgumentException(
						"Missing required parameter '" + ent.getKey() + "'");
				}
				continue; // Should not need to check the default value
			}
			Object arg = arguments.get(ent.getKey());
			if (arg instanceof TraceObject obj) {
				if (trace == null) {
					trace = obj.getTrace();
					ctx = trace.getObjectManager().getRootSchema().getContext();
				}
				else if (trace != obj.getTrace()) {
					throw new IllegalArgumentException(
						"All TraceObject parameters must come from the same trace");
				}
			}
			TargetObjectSchema sch = ctx.getSchema(ent.getValue().type());
			checkType(ent.getKey(), sch, arg);
		}
		for (Map.Entry<String, Object> ent : arguments.entrySet()) {
			if (!parameters().containsKey(ent.getKey())) {
				throw new IllegalArgumentException("Extra argument '" + ent.getKey() + "'");
			}
		}
		return trace;
	}

	/**
	 * Invoke the remote method, getting a future result.
	 * 
	 * <p>
	 * This invokes the method asynchronously. The returned objects is a {@link CompletableFuture},
	 * whose getters are overridden to prevent blocking the Swing thread for more than 1 second. Use
	 * of this method is not recommended, if it can be avoided; however, you should not create a
	 * thread whose sole purpose is to invoke this method. UI actions that need to invoke a remote
	 * method should do so using this method, but they must be sure to handle errors using, e.g.,
	 * using {@link CompletableFuture#exceptionally(Function)}, lest the actions fail silently.
	 * 
	 * @param arguments the keyword arguments to the remote method
	 * @return the future result
	 * @throws IllegalArgumentException if the arguments are not valid
	 */
	RemoteAsyncResult invokeAsync(Map<String, Object> arguments);

	/**
	 * Invoke the remote method and wait for its completion.
	 * 
	 * <p>
	 * This method cannot be invoked from the Swing thread. This is to avoid locking up the user
	 * interface. If you are on the Swing thread, consider {@link #invokeAsync(Map)} instead. You
	 * can chain the follow-up actions and then schedule any UI updates on the Swing thread using
	 * {@link AsyncUtils#SWING_EXECUTOR}.
	 * 
	 * @param arguments the keyword arguments to the remote method
	 * @throws IllegalArgumentException if the arguments are not valid
	 */
	default Object invoke(Map<String, Object> arguments) {
		try {
			return invokeAsync(arguments).get();
		}
		catch (InterruptedException | ExecutionException e) {
			throw new TraceRmiError(e);
		}
	}

	record RecordRemoteMethod(TraceRmiHandler handler, String name, Action action,
			String description, Map<String, RemoteParameter> parameters, SchemaName retType)
			implements RemoteMethod {
		@Override
		public RemoteAsyncResult invokeAsync(Map<String, Object> arguments) {
			Trace trace = validate(arguments);
			OpenTrace open = handler.getOpenTrace(trace);
			return handler.invoke(open, name, arguments);
		}
	}
}
