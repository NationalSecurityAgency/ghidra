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
package ghidra.dbg;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.RejectedExecutionException;
import java.util.function.Predicate;

import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.error.*;
import ghidra.dbg.target.TargetMemory;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.EnumerableTargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;
import ghidra.util.Msg;

/**
 * A debugger model, often a connection to an external debugger
 * 
 * <p>
 * This is an abstraction of debugger operations and attempts to limit assumptions to those that
 * generalize to most platforms. Debuggers and the target processes may be temperamental, so an
 * asynchronous pattern is employed to prevent deadlocks on dropped connections, slow connections,
 * buggy daemons, etc.
 * 
 * <p>
 * For methods returning a {@link CompletableFuture}, the documentation describes its return value
 * assuming successful completion. Any of the futures may complete exceptionally.
 * 
 * <p>
 * The completion of any future returned by a method does not imply any state change in the
 * debugger. It merely acknowledges that the request was received by the debugger. Only listener
 * callbacks confirm or otherwise communicate actual state changes. If, in the underlying protocol,
 * confirmation of a request implies a state change, then the implementation must make the
 * appropriate callbacks.
 * 
 * <p>
 * The model object only exposes the connection state and a root object. The model comprises an
 * arbitrary tree of {@link TargetObject}s each supporting zero or more discoverable interfaces. The
 * debugging framework provides a number of "stock" interfaces which should be sufficient to model
 * most debuggers. The tree is how the client accesses objects, e.g., processes and threads, on the
 * target.
 * 
 * <p>
 * Users and implementors of this interface may find {@link AsyncUtils} useful. An implementation of
 * this interface should never block the calling thread to wait on an external event, otherwise, you
 * risk deadlocking Ghidra's UI.
 */
public interface DebuggerObjectModel {
	public static final TypeSpec<Map<String, ? extends TargetObject>> ELEMENT_MAP_TYPE =
		TypeSpec.auto();
	public static final TypeSpec<Map<String, ?>> ATTRIBUTE_MAP_TYPE = TypeSpec.auto();

	/**
	 * Check that a given {@link TargetObject} interface has a name
	 * 
	 * <p>
	 * Names are assigned using the {@link DebuggerTargetObjectIface} annotation.
	 * 
	 * @implNote To be language agnostic, we never use the name of the Java implementation of the
	 *           interface.
	 * 
	 * @param iface the class of the interface
	 * @return the name of the interface
	 * @throws IllegalArgumentException if the interface is not annotated
	 */
	public static String requireIfaceName(Class<? extends TargetObject> iface) {
		DebuggerTargetObjectIface annot = iface.getAnnotation(DebuggerTargetObjectIface.class);
		if (annot == null) {
			throw new IllegalArgumentException(iface + " has no @" +
				DebuggerTargetObjectIface.class.getSimpleName() + " annotation.");
		}
		return annot.value();
	}

	/**
	 * Check that the given value is not null
	 * 
	 * @param <T> the type of the value
	 * @param val the value
	 * @param path the path where the value was expected
	 * @return the non-null value
	 * @throws DebuggerModelNoSuchPathException if -val- is null
	 */
	public static <T> T requireNonNull(T val, List<String> path) {
		if (val == null) {
			throw new DebuggerModelNoSuchPathException("Path " + path + " does not exist");
		}
		return val;
	}

	/**
	 * Check that the given object is non-null and supports a required interface
	 * 
	 * <p>
	 * Because most of the {@link TargetObject} interfaces have a (self-referential) type parameter,
	 * this call will most likely be on its own line, assigned to a variable of the interface type
	 * using a wildcard {@code <?>} parameter. Otherwise, raw types get involved, making things
	 * rather messy.
	 * 
	 * @param <T> the type of the interface
	 * @param iface the class for the interface
	 * @param obj the object to check
	 * @param path the path where the object was expected
	 * @return the (non-null) object cast to the required interface
	 * @throws DebuggerModelNoSuchPathException if -obj- is null
	 * @throws DebuggerModelTypeException if -obj- does not support -iface-
	 */
	public static <T extends TargetObject> T requireIface(Class<T> iface, TargetObject obj,
			List<String> path) {
		requireNonNull(obj, path);
		String name = requireIfaceName(iface);
		if (iface.isAssignableFrom(obj.getClass())) {
			return iface.cast(obj);
		}
		throw new DebuggerModelTypeException("Object " + path + " is missing " + name);
	}

	/**
	 * Get a brief description of the client, suitable for display in lists
	 * 
	 * @return the description
	 */
	public default String getBrief() {
		return toString();
	}

	/**
	 * Add a listener for model events
	 * 
	 * <p>
	 * If requested, the listener is notified of existing objects via an event replay. It will first
	 * replay all the created events in the same order they were originally emitted. Any objects
	 * which have since been invalidated are excluded in the replay. They don't exist anymore, after
	 * all. Next it will replay the attribute- and element-added events in post order. This is an
	 * attempt to ensure an object's dependencies are met by the time the client receives its added
	 * event. This isn't always possible due to cycles, but such cycles are usually informational.
	 * 
	 * @param listener the listener
	 * @param replay true to replay object tree events (doesn't include register or memory caches)
	 */
	public void addModelListener(DebuggerModelListener listener, boolean replay);

	/**
	 * Add a listener for model events, without replay
	 * 
	 * @param listener the listener
	 */
	public default void addModelListener(DebuggerModelListener listener) {
		addModelListener(listener, false);
	}

	/**
	 * Remove a model event listener
	 * 
	 * @param listener the listener
	 */
	public void removeModelListener(DebuggerModelListener listener);

	/**
	 * Check if the model believes it is alive
	 * 
	 * <p>
	 * Basically, this should be true if the model has started, but not yet terminated. To test
	 * whether the model is actually responsive, use {@link #ping(String)}.
	 * 
	 * @return true if alive
	 */
	public boolean isAlive();

	/**
	 * Get the schema of this model, i.e., the schema of its root object.
	 * 
	 * <p>
	 * The schema may not be known until the model has been successfully opened. Some factories will
	 * ensure success before providing the model, but this may not always be the case. Callers
	 * should listen for {@link DebuggerModelListener#modelOpened()} or retrieve the root object
	 * first.
	 * 
	 * @return the root schema
	 */
	public default TargetObjectSchema getRootSchema() {
		return EnumerableTargetObjectSchema.OBJECT;
	}

	/**
	 * Check if the debugger agent is alive (optional operation)
	 * 
	 * <p>
	 * For models providing such a mechanism, check if the debugger is alive and able to process
	 * commands. Even if an explicit "ping" command is not available, an implementor is encouraged
	 * to use some sort of NOP or echo command to test for responsiveness.
	 * 
	 * @param content some content to optionally incorporate into the test
	 * @return a future that completes when the daemon is verified to be alive
	 */
	public CompletableFuture<Void> ping(String content);

	/**
	 * Check that a given reference (or object) belongs to this model
	 * 
	 * <p>
	 * As a convenience, this method takes an expected class and casts -ref- to it. This is meant
	 * only to cast to an implementation-specific type, not for checking that an object supports a
	 * given interface. Use {@link #requireIface(Class, TargetObject, List)} for interface checking.
	 * 
	 * @param <T> the required implementation-specific type
	 * @param cls the class for the required type
	 * @param obj the object to check
	 * @return the object, cast to the desired typed
	 * @throws DebuggerIllegalArgumentException if {@code obj} does not belong to this model
	 */
	default <T extends TargetObject> T assertMine(Class<T> cls, TargetObject obj) {
		if (obj.getModel() != this) {
			throw new DebuggerIllegalArgumentException(
				"TargetObject " + obj + " does not belong to this model");
		}
		return cls.cast(obj);
	}

	/**
	 * Fetch the attributes of a given model path
	 * 
	 * <p>
	 * Giving an empty path will retrieve the attributes of the root object. If the path does not
	 * exist, the future completes with {@code null}.
	 * 
	 * @param path the path
	 * @param refresh true to invalidate caches involved in handling this request
	 * @return a future map of attributes
	 */
	public CompletableFuture<? extends Map<String, ?>> fetchObjectAttributes(List<String> path,
			boolean refresh);

	/**
	 * Fetch the attributes of the given model path, without refreshing
	 * 
	 * @see #fetchObjectAttributes(List, boolean)
	 */
	public default CompletableFuture<? extends Map<String, ?>> fetchObjectAttributes(
			List<String> path) {
		return fetchObjectAttributes(path, false);
	}

	/**
	 * @see #fetchObjectAttributes(List)
	 */
	public default CompletableFuture<? extends Map<String, ?>> fetchObjectAttributes(
			String... path) {
		return fetchObjectAttributes(List.of(path));
	}

	/**
	 * Fetch the elements of a given model path
	 * 
	 * <p>
	 * Giving an empty path will retrieve all the top-level objects, i.e., elements of the root. If
	 * the path does not exist, the future completes with {@code null}.
	 * 
	 * @param path the path
	 * @param refresh true to invalidate caches involved in handling this request
	 * @return a future map of elements
	 */
	public CompletableFuture<? extends Map<String, ? extends TargetObject>> fetchObjectElements(
			List<String> path, boolean refresh);

	/**
	 * Fetch the elements of the given model path, without refreshing
	 * 
	 * @see #fetchObjectElements(List, boolean)
	 */
	public default CompletableFuture<? extends Map<String, ? extends TargetObject>> fetchObjectElements(
			List<String> path) {
		return fetchObjectElements(path, false);
	}

	/**
	 * @see #fetchObjectElements(List)
	 */
	public default CompletableFuture<? extends Map<String, ? extends TargetObject>> fetchObjectElements(
			String... path) {
		return fetchObjectElements(List.of(path));
	}

	/**
	 * Fetch the root object of the model
	 * 
	 * <p>
	 * The root is a virtual object to contain all the top-level objects of the model tree. This
	 * object represents the debugger itself. Note in most cases {@link #getModelRoot()} is
	 * sufficient; however, if you've just created the model, it is prudent to wait for it to create
	 * its root. For asynchronous cases, just listen for the root-creation and -added events. This
	 * method returns a future which completes after the root-added event.
	 * 
	 * @return a future which completes with the root
	 */
	public CompletableFuture<? extends TargetObject> fetchModelRoot();

	/**
	 * Get the root object of the model
	 * 
	 * @return the root or {@code null} if it hasn't been created, yet
	 */
	public TargetObject getModelRoot();

	/**
	 * Fetch the value at the given path
	 * 
	 * @param path the path of the value
	 * @return a future completing with the value or with {@code null} if the path does not exist
	 */
	public CompletableFuture<?> fetchModelValue(List<String> path);

	/**
	 * Fetch a model value, optionally refreshing caches along the path
	 * 
	 * <p>
	 * By convention, no attribute nor element may have a {@code null} value. Thus, a {@code null}
	 * return value always indicates the path does not exist.
	 * 
	 * <p>
	 * When refresh is true, only the applicable cache at each successor is refreshed. For example,
	 * when the path is {@code A.B[1].C[2]}, then only {@code B}'s and {@code C}'s element caches
	 * are refreshed; and {@code A}'s, {@code B[1]}'s, and {@code C[2]}'s attribute caches are
	 * refreshed.
	 * 
	 * @param path the path
	 * @param refresh true to refresh caches
	 * @return the found value, or {@code null} if it does not exist
	 */
	public CompletableFuture<?> fetchModelValue(List<String> path, boolean refresh);

	/**
	 * @see #fetchModelValue(List)
	 */
	public default CompletableFuture<?> fetchModelValue(String... path) {
		return fetchModelValue(List.of(path));
	}

	/**
	 * Get the value at a given path
	 * 
	 * <p>
	 * If the path does not exist, null is returned. Note that an attempt to access the child of a
	 * primitive is the same as accessing a path that does not exist; however, an error will be
	 * logged, since this typically indicates a programming error.
	 * 
	 * @param path the path
	 * @return the value
	 */
	public default Object getModelValue(List<String> path) {
		Object cur = getModelRoot();
		for (String key : path) {
			if (cur == null) {
				return null;
			}
			if (!(cur instanceof TargetObject)) {
				Msg.error(this, "Primitive " + cur + " cannot have child '" + key + "'");
				return null;
			}
			TargetObject obj = (TargetObject) cur;
			if (PathUtils.isIndex(key)) {
				cur = obj.getCachedElements().get(PathUtils.parseIndex(key));
				continue;
			}
			assert PathUtils.isName(key);
			cur = obj.getCachedAttribute(key);
		}
		return cur;
	}

	/**
	 * Fetch the object with the given path
	 * 
	 * <p>
	 * If the value at the path is a link, this will attempt to fetch it.
	 * 
	 * @param path the path of the object
	 * @param refresh ignore the cache
	 * @return a future completing with the object or with {@code null} if it does not exist
	 * @throws DebuggerModelTypeException if the value at the path is not a {@link TargetObject}
	 */
	public default CompletableFuture<? extends TargetObject> fetchModelObject(List<String> path,
			boolean refresh) {
		return fetchModelValue(path, refresh).thenApply(v -> {
			if (v == null) {
				return null;
			}
			if (!(v instanceof TargetObject)) {
				throw DebuggerModelTypeException.typeRequired(v, path, TargetObject.class);
			}
			return (TargetObject) v;
		});
	}

	/**
	 * Get an object from the model, resyncing according to the schema
	 * 
	 * <p>
	 * This is necessary when an object in the path has a resync mode other than
	 * {@link ResyncMode#NEVER} for the child being retrieved. Please note that some synchronization
	 * may still be required on the client side, since accessing the object before it is created
	 * will cause a {@code null} completion.
	 * 
	 * @return a future that completes with the object or with {@code null} if it doesn't exist
	 */
	@Deprecated
	public default CompletableFuture<? extends TargetObject> fetchModelObject(List<String> path) {
		return fetchModelObject(path, false);
	}

	/**
	 * Get an object from the model
	 * 
	 * <p>
	 * Note this may return an object which is still being constructed, i.e., between being created
	 * and being added to the model. This differs from {@link #getModelValue(List)}, which will only
	 * return an object after it has been added. This method also never follows links.
	 * 
	 * @param path the path of the object
	 * @return the object or {@code null} if it doesn't exist
	 */
	public TargetObject getModelObject(List<String> path);

	/**
	 * Get all created objects matching a given predicate
	 * 
	 * <p>
	 * Note the predicate is executed while holding an internal model-wide lock. Be careful and keep
	 * it simple.
	 * 
	 * @param predicate the predicate
	 * @return the set of matching objects
	 */
	public Set<TargetObject> getModelObjects(Predicate<? super TargetObject> predicate);

	/**
	 * @see #fetchModelObject(List)
	 */
	@Deprecated
	public default CompletableFuture<? extends TargetObject> fetchModelObject(String... path) {
		return fetchModelObject(List.of(path));
	}

	/**
	 * @see #getModelObject(List)
	 */
	public default TargetObject getModelObject(String... path) {
		return getModelObject(List.of(path));
	}

	/**
	 * Fetch the attribute with the given path
	 * 
	 * Note that model implementations should avoid nullable attributes, since a null-valued
	 * attribute cannot easily be distinguished from a non-existent attribute.
	 * 
	 * @param path the path of the attribute
	 * @return a future that completes with the value or with {@code null} if it does not exist
	 */
	public default CompletableFuture<?> fetchObjectAttribute(List<String> path) {
		return fetchModelObject(PathUtils.parent(path)).thenApply(
			parent -> parent == null ? null : parent.fetchAttribute(PathUtils.getKey(path)));
	}

	/**
	 * @see #fetchObjectAttribute(List)
	 */
	public default CompletableFuture<?> getObjectAttribute(String... path) {
		return fetchObjectAttribute(List.of(path));
	}

	/**
	 * Get a factory for target addresses
	 * 
	 * <p>
	 * Technically, putting this here instead of just {@link TargetMemory} imposes a subtle
	 * limitation: All targets in the model have to have the same factory. I'm not certain that's a
	 * huge concern at this point. The alternative is that the memory mapper has to accept and
	 * compose new address factories, or we need a separate mapper per factory encountered along
	 * with a mechanism to choose the correct one.
	 * 
	 * @return the factory
	 */
	public AddressFactory getAddressFactory();

	/**
	 * TODO Document me
	 * 
	 * @param name
	 * @return
	 */
	default public AddressSpace getAddressSpace(String name) {
		return getAddressFactory().getAddressSpace(name);
	}

	/**
	 * TODO Document me
	 * 
	 * @param space
	 * @param offset
	 * @return
	 */
	public default Address getAddress(String space, long offset) {
		if (Address.NO_ADDRESS.getAddressSpace().getName().equals(space)) {
			return Address.NO_ADDRESS;
		}
		return getAddressSpace(space).getAddress(offset);
	}

	/**
	 * Invalidate the caches for every object known locally.
	 * 
	 * <p>
	 * Unlike, {@link TargetObject#invalidateCaches()}, this does not push the request to a remote
	 * object. If the objects are proxies, just the proxies' caches are cleared. Again, this does
	 * not apply to caches for the objects' children.
	 */
	public void invalidateAllLocalCaches();

	/**
	 * Close the session and dispose the model
	 * 
	 * <p>
	 * For local sessions, terminate the debugger. For client sessions, disconnect.
	 * 
	 * @return a future which completes when the session is closed
	 */
	public CompletableFuture<Void> close();

	/**
	 * A convenience for reporting errors conditionally
	 * 
	 * <p>
	 * If the message is ignorable, e.g., a {@link DebuggerModelTerminatingException}, then the
	 * report will be reduced to a stack-free warning.
	 * 
	 * @param origin the object producing the error
	 * @param message the error message
	 * @param ex the exception
	 */
	default void reportError(Object origin, String message, Throwable ex) {
		if (ex == null || DebuggerModelTerminatingException.isIgnorable(ex)) {
			Msg.warn(origin, message + ": " + ex);
		}
		else if (AsyncUtils.unwrapThrowable(ex) instanceof RejectedExecutionException) {
			Msg.trace(origin, "Ignoring rejection", ex);
		}
		else {
			Msg.error(origin, message, ex);
		}
	}

	/**
	 * Permit all callbacks to be invoked before proceeding
	 * 
	 * <p>
	 * This operates by placing the request into the queue itself, so that any event callbacks
	 * queued <em>at the time of the flush invocation</em> are completed first. There are no
	 * guarantees with respect to events which get queued <em>after the flush invocation</em>.
	 * 
	 * @return a future which completes when all queued callbacks have been invoked
	 */
	CompletableFuture<Void> flushEvents();
}
