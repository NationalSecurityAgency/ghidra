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
package ghidra.debug.api.tracermi;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.Function;

import ghidra.async.AsyncUtils;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.debug.api.target.ActionName;
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
	ActionName action();

	/**
	 * A title to display in the UI for this action.
	 * 
	 * @return the title
	 */
	String display();

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
	 * @param paramName the name of the parameter
	 * @param schName the name of the parameter's schema
	 * @param sch the type of the parameter
	 * @param arg the argument
	 */
	static void checkType(String paramName, SchemaName schName, TargetObjectSchema sch,
			Object arg) {
		// if sch is null, it was definitely an object-type schema without context
		if (sch != null) {
			if (sch.getType() != TargetObject.class) {
				if (sch.getType().isInstance(arg)) {
					return;
				}
			}
			else if (arg instanceof TraceObject obj) {
				if (sch.isAssignableFrom(obj.getTargetSchema())) {
					return;
				}
			}
		}
		throw new IllegalArgumentException(
			"For parameter %s: argument %s is not a %s".formatted(paramName, arg, schName));
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
			SchemaName schName = ent.getValue().type();
			TargetObjectSchema sch = ctx.getSchemaOrNull(schName);
			checkType(ent.getKey(), schName, sch, arg);
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
	 * @return the returned value
	 */
	default Object invoke(Map<String, Object> arguments) {
		try {
			return invokeAsync(arguments).get();
		}
		catch (InterruptedException | ExecutionException e) {
			throw new TraceRmiError(e);
		}
	}
}
