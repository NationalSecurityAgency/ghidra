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

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.error.DebuggerModelNoSuchPathException;
import ghidra.dbg.error.DebuggerModelTypeException;
import ghidra.dbg.target.TargetMemory;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;

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
	 * @param listener the listener
	 */
	public void addModelListener(DebuggerModelListener listener);

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
	 * @param ref the reference (or object) to check
	 * @return the object, cast to the desired typed
	 * @throws IllegalArgumentException if -ref- does not belong to this model
	 */
	default <T extends TargetObjectRef> T assertMine(Class<T> cls, TargetObjectRef ref) {
		if (ref.getModel() != this) {
			throw new IllegalArgumentException(
				"TargetObject (or ref)" + ref + " does not belong to this model");
		}
		return cls.cast(ref);
	}

	/**
	 * Create a reference to the given path in this model
	 * 
	 * Note that the path is not checked until the object is fetched. Thus, it is possible for a
	 * reference to refer to a non-existent object.
	 * 
	 * @param path the path of the object
	 * @return a reference to the object
	 */
	public TargetObjectRef createRef(List<String> path);

	/**
	 * @see #createRef(List)
	 */
	public default TargetObjectRef createRef(String... path) {
		return createRef(List.of(path));
	}

	/**
	 * Fetch the attributes of a given model path
	 * 
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
	 * Giving an empty path will retrieve all the top-level objects, i.e., elements of the root. If
	 * the path does not exist, the future completes with {@code null}.
	 * 
	 * @param path the path
	 * @param refresh true to invalidate caches involved in handling this request
	 * @return a future map of elements
	 */
	public CompletableFuture<? extends Map<String, ? extends TargetObjectRef>> fetchObjectElements(
			List<String> path, boolean refresh);

	/**
	 * Fetch the elements of the given model path, without refreshing
	 * 
	 * @see #fetchObjectElements(List, boolean)
	 */
	public default CompletableFuture<? extends Map<String, ? extends TargetObjectRef>> fetchObjectElements(
			List<String> path) {
		return fetchObjectElements(path, false);
	}

	/**
	 * @see #fetchObjectElements(List)
	 */
	public default CompletableFuture<? extends Map<String, ? extends TargetObjectRef>> fetchObjectElements(
			String... path) {
		return fetchObjectElements(List.of(path));
	}

	/**
	 * Fetch the root object of the model
	 * 
	 * The root is a virtual object to contain all the top-level objects of the model tree. This
	 * object represents the debugger itself.
	 * 
	 * @return the root
	 */
	public CompletableFuture<? extends TargetObject> fetchModelRoot();

	/**
	 * Fetch the value at the given path
	 * 
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
	 * @implNote The returned value cannot be a {@link TargetObjectRef} unless the value represents
	 *           a link. In other words, if the path refers to an object, the model must return the
	 *           object, not a ref. When the value is a link, the implementation may optionally
	 *           resolve the object, but should only do so if it doesn't incur a significant cost.
	 *           Furthermore, such links cannot be resolved -- though they can be substituted for
	 *           the target object at the linked path. In other words, the path of the returned ref
	 *           (or object) must represent the link's target. Suppose {@code A[1]} is a link to
	 *           {@code B[1]}, which is in turn a link to {@code C[1]} -- honestly, linked links
	 *           ought to be a rare occurrence -- then fetching {@code A[1]} must return a ref to
	 *           {@code B[1]}. It must not return {@code C[1]} nor a ref to it. The reason deals
	 *           with caching and updates. If a request for {@code A[1]} were to return
	 *           {@code C[1]}, a client may cache that result. Suppose that client then observes a
	 *           change causing {@code B[1]} to link to {@code C[2]}. This implies that {@code A[1]}
	 *           now resolves to {@code C[2]}; however, the client has not received enough
	 *           information to update or invalidate its cache.
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
		return fetchModelValue(path, refresh).thenCompose(v -> {
			if (v == null) {
				return AsyncUtils.nil();
			}
			if (!(v instanceof TargetObjectRef)) {
				throw DebuggerModelTypeException.typeRequired(v, path, TargetObjectRef.class);
			}
			TargetObjectRef ref = (TargetObjectRef) v;
			if (path.equals(ref.getPath()) && !(v instanceof TargetObject)) {
				throw DebuggerModelTypeException.typeRequired(v, path, TargetObject.class);
			}
			return ref.fetch();
		});
	}

	/**
	 * @see #fetchModelObject(List)
	 */
	public default CompletableFuture<? extends TargetObject> fetchModelObject(List<String> path) {
		return fetchModelObject(path, false);
	}

	/**
	 * @see #fetchModelObject(List)
	 */
	public default CompletableFuture<? extends TargetObject> fetchModelObject(String... path) {
		return fetchModelObject(List.of(path));
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
	 * Unlike, {@link TargetObject#invalidateCaches()}, this does not push the request to a remote
	 * object. If the objects are proxies, just the proxies' caches are cleared. Again, this does
	 * not apply to caches for the objects' children.
	 */
	public void invalidateAllLocalCaches();

	/**
	 * Close the session and dispose the model
	 * 
	 * For local sessions, terminate the debugger. For client sessions, disconnect.
	 * 
	 * @return a future which completes when the session is closed
	 */
	public CompletableFuture<Void> close();

}
