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
package ghidra.dbg.target;

import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import ghidra.async.AsyncFence;
import ghidra.async.AsyncUtils;
import ghidra.dbg.*;
import ghidra.dbg.error.DebuggerModelTypeException;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.dbg.util.PathUtils.PathComparator;
import ghidra.dbg.util.PathUtils.TargetObjectKeyComparator;
import ghidra.dbg.util.ValueUtils;
import ghidra.lifecycle.Internal;

/**
 * A handle to a target object in a debugger
 * 
 * <p>
 * This object supports querying for and obtaining the interfaces which constitute what the object
 * is and define how the client may interact with it. The object may also have children, e.g., a
 * process should likely have threads.
 * 
 * <p>
 * This interface is the focal point of the "debug target model." A debugger may present itself as
 * an arbitrary directory of "target objects." The root object is typically the debugger's session,
 * and one its attributes is a collection for its attached targets. These objects, including the
 * root object, may implement any number of interfaces extending {@link TargetObject}. These
 * interfaces comprise the type and behavior of the object. An object's children comprise its
 * elements (for collection-like objects) and attributes. Every object in the directory has a path.
 * Each element ("key") in the path identifies an index (if the child is an element) or a name (if
 * the child is an attribute). It is the implementation's responsibility to ensure each object's
 * path correctly identifies that same object in the model directory. The root has the empty path.
 * Every object must have a unique path; thus, every object must have a unique key among its
 * sibling.
 * 
 * <p>
 * The objects are arranged in a directory with links permitted. Links come in the form of
 * object-valued attributes or elements where the path does not match the object value's path. Thus,
 * the overall structure remains a tree, but by resolving links, the model may be treated as a
 * directed graph, likely containing cycles. See {@link PathUtils#isLink(List, String, List)}.
 * 
 * <p>
 * The implementation must guarantee that distinct {@link TargetObject}s from the same model do not
 * share the same path. That is, checking for object identity is sufficient to check that two
 * variables refer to the same object.
 * 
 * <p>
 * Various conventions govern where the client/user should search to obtain a given interface in the
 * context of some target object. For example, if the user is interacting with a thread, and wishes
 * to access that thread's memory, it needs to follow a given search order to find the appropriate
 * target object(s), if they exist, implementing the desired interface. See
 * {@link DebugModelConventions#findSuitable(Class, TargetObject)} and
 * {@link DebugModelConventions#findInAggregate(Class, TargetObject)} for details. In summary, the
 * order is:
 * 
 * <ol>
 * <li><b>The object itself:</b> Test if the context target object supports the desired interface.
 * If it does, take it.</li>
 * <li><b>Aggregate objects:</b> If the object is marked with {@link TargetAggregate}, collect all
 * attributes supporting the desired interface. If there are any, take them. This step is applied
 * recursively if any child attribute is also marked with {@link TargetAggregate}.</li>
 * <li><b>Ancestry:</b> Apply these same steps to the object's (canonical) parent, recursively.</li>
 * </ol>
 * 
 * <p>
 * For some situations, exactly one object is required. In that case, take the first obtained by
 * applying the above rules. In other situations, multiple objects may be acceptable. Again, apply
 * the rules until a sufficient collection of objects is obtained. If an object is in conflict with
 * another, take the first encountered. This situation may be appropriate if, e.g., multiple target
 * memories present disjoint regions. There should not be conflicts among sibling. If there are,
 * then either the model or the query is not sound. The order siblings considered should not matter.
 * These rules are incubating and are implemented in {@link DebugModelConventions}.
 * 
 * <p>
 * This relatively free structure and corresponding conventions allow for debuggers to present a
 * model which closely reflects the structure of its session. For example, the following structure
 * may be presented by a user-space debugger for a desktop operating system:
 * 
 * <ul>
 * <li>"Session" : {@link TargetAccessConditioned}, {@link TargetInterpreter},
 * {@link TargetAttacher}, {@link TargetLauncher}, {@link TargetInterruptible}</li>
 * <ul>
 * <li>"Process 789" : {@link TargetAggregate}, {@link TargetDetachable}, {@link TargetKillable},
 * {@link TargetResumable}</li>
 * <ul>
 * <li>"Threads" : {@link TargetObject}</li>
 * <ul>
 * <li>"Thread 1" : {@link TargetExecutionStateful}, {@link TargetSingleSteppable},
 * {@link TargetMultiSteppable}</li>
 * <ul>
 * <li>"Registers" : {@link TargetRegisterBank}</li>
 * <ul>
 * <li>"r1" : {@link TargetRegister}</li>
 * <li>...</li>
 * </ul>
 * </ul>
 * <li>...more threads</li>
 * </ul>
 * <li>"Memory" : {@link TargetMemory}</li>
 * <ul>
 * <li>"[0x00400000:0x00401234]" : {@link TargetMemoryRegion}</li>
 * <li>...more regions</li>
 * </ul>
 * <li>"Modules" : {@link TargetModuleContainer}</li>
 * <ul>
 * <li>"/usr/bin/echo" : {@link TargetModule}</li>
 * <ul>
 * <li>".text" ({@link TargetSection})</li>
 * <li>...more sections</li>
 * <li>"Namespace" : {@link TargetSymbolNamespace}</li>
 * <ul>
 * <li>"main" : {@link TargetSymbol}</li>
 * <li>"astruct" : {@link TargetNamedDataType}</li>
 * <li>...more symbols and types</li>
 * </ul>
 * </ul>
 * <li>...more modules</li>
 * </ul>
 * </ul>
 * <li>"Environment": {@link TargetEnvironment}</li>
 * <ul>
 * <li>"Process 321" : {@link TargetAttachable}</li>
 * <li>...more processes</li>
 * </ul>
 * </ul>
 * </ul>
 * 
 * <p>
 * TODO: Should I have a different type for leaf vs. branch objects? Attribute-/element-only
 * objects?
 * 
 * <p>
 * Note that several methods of this interface and its sub-types return {@link CompletableFuture},
 * because they are actions which may be transported over a network, or otherwise require
 * asynchronous communication with a debugger. The documentation may say these methods return an
 * object or throw an exception. In those cases, unless otherwise noted, this actually means the
 * future will complete with that object, or complete exceptionally. Specifying this in every
 * instance is just pedantic.
 */
public interface TargetObject extends Comparable<TargetObject> {

	Set<Class<? extends TargetObject>> ALL_INTERFACES =
		Set.of(TargetAccessConditioned.class, TargetActiveScope.class, TargetAggregate.class,
			TargetAttachable.class, TargetAttacher.class, TargetBreakpointLocation.class,
			TargetBreakpointLocationContainer.class, TargetBreakpointSpec.class,
			TargetBreakpointSpecContainer.class, TargetConfigurable.class, TargetConsole.class,
			TargetDataTypeMember.class, TargetDataTypeNamespace.class, TargetDeletable.class,
			TargetDetachable.class, TargetEnvironment.class, TargetEventScope.class,
			TargetExecutionStateful.class, TargetFocusScope.class, TargetInterpreter.class,
			TargetInterruptible.class, TargetKillable.class, TargetLauncher.class,
			TargetMemory.class, TargetMemoryRegion.class, TargetMethod.class, TargetModule.class,
			TargetModuleContainer.class, TargetNamedDataType.class, TargetProcess.class,
			TargetRegister.class, TargetRegisterBank.class, TargetRegisterContainer.class,
			TargetResumable.class, TargetSection.class, TargetSectionContainer.class,
			TargetStack.class, TargetStackFrame.class, TargetSteppable.class, TargetSymbol.class,
			TargetSymbolNamespace.class, TargetThread.class, TargetTogglable.class);
	Map<String, Class<? extends TargetObject>> INTERFACES_BY_NAME = initInterfacesByName();

	/**
	 * Initializer for {@link #INTERFACES_BY_NAME}
	 * 
	 * @return interfaces indexed by name
	 */
	@Internal
	static Map<String, Class<? extends TargetObject>> initInterfacesByName() {
		return ALL_INTERFACES.stream()
				.collect(
					Collectors.toUnmodifiableMap(DebuggerObjectModel::requireIfaceName, i -> i));
	}

	static List<Class<? extends TargetObject>> getInterfacesByName(Collection<String> names) {
		return names.stream()
				.filter(INTERFACES_BY_NAME::containsKey)
				.map(INTERFACES_BY_NAME::get)
				.collect(Collectors.toList());
	}

	/**
	 * A conventional prefix of hidden attributes defined by the {@code TargetObject} interfaces
	 * 
	 * <p>
	 * When the "hidden" field of attributes can be overridden, this prefix should be removed
	 */
	String PREFIX_INVISIBLE = "_";

	String DISPLAY_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "display";
	String SHORT_DISPLAY_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "short_display";
	String KIND_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "kind";
	String ORDER_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "order";

	// TODO: Should these belong to a new TargetValue interface?
	String MODIFIED_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "modified";
	String TYPE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "type";
	String VALUE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "value";

	enum Protected {
		;
		protected static final Map<Class<? extends TargetObject>, Collection<Class<? extends TargetObject>>> INTERFACES_BY_CLASS =
			new HashMap<>();
		protected static final Map<Class<? extends TargetObject>, Collection<String>> INTERFACE_NAMES_BY_CLASS =
			new HashMap<>();

		/**
		 * Get all {@link DebuggerTargetObjectIface}-annotated interfaces in the given class's
		 * hierarchy.
		 * 
		 * @param cls the class
		 */
		protected static Collection<Class<? extends TargetObject>> getInterfacesOf(
				Class<? extends TargetObject> cls) {
			return INTERFACES_BY_CLASS.computeIfAbsent(cls, Protected::doGetInterfacesOf);
		}

		protected static Collection<Class<? extends TargetObject>> doGetInterfacesOf(
				Class<? extends TargetObject> cls) {
			List<Class<? extends TargetObject>> result = new ArrayList<>();
			doCollectInterfaces(cls, result);
			return result;
		}

		protected static void doCollectInterfaces(Class<?> cls,
				Collection<Class<? extends TargetObject>> result) {
			if (TargetObject.class == cls) {
				return;
			}
			if (!TargetObject.class.isAssignableFrom(cls)) {
				return;
			}
			if (cls.isInterface()) {
				result.add(cls.asSubclass(TargetObject.class));
			}
			Class<?> sup = cls.getSuperclass();
			if (sup != null) {
				doCollectInterfaces(sup, result);
			}
			for (Class<?> si : cls.getInterfaces()) {
				doCollectInterfaces(si, result);
			}
		}

		public static Collection<String> getInterfaceNamesOf(Class<? extends TargetObject> cls) {
			return INTERFACE_NAMES_BY_CLASS.computeIfAbsent(cls, Protected::doGetInterfaceNamesOf);
		}

		protected static Collection<String> doGetInterfaceNamesOf(
				Class<? extends TargetObject> cls) {
			List<String> result = new ArrayList<>();
			for (Class<? extends TargetObject> iface : getInterfacesOf(cls)) {
				DebuggerTargetObjectIface annot =
					iface.getAnnotation(DebuggerTargetObjectIface.class);
				if (annot == null) {
					continue;
				}
				result.add(annot.value());
			}
			result.sort(Comparator.naturalOrder());
			return result;
		}
	}

	/**
	 * Check for target object equality
	 * 
	 * <p>
	 * Because interfaces cannot provide default implementations of {@link #equals(Object)}, this
	 * methods provides a means of quickly implementing it within a class. Because (model, path)
	 * uniquely identifies an object, there should never be a need to perform more comparison than
	 * is provided here.
	 * 
	 * <p>
	 * TODO: Since refs are no longer a thing, is custom equality needed at all? Seems object
	 * identity would be sufficient.
	 * 
	 * @param obj the other object
	 * @return true if they are equal
	 */
	default boolean doEquals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof TargetObject)) {
			return false;
		}
		TargetObject that = (TargetObject) obj;
		return this.getModel() == that.getModel() && Objects.equals(this.getPath(), that.getPath());
	}

	/**
	 * Pre-compute this object's hash code
	 * 
	 * <p>
	 * Because interfaces cannot provide default implementations of {@link #hashCode()}, this method
	 * provides a means of quickly implementing it within a class. Because (model, path) is
	 * immutable and uniquely identifes an object, this hash should be pre-computed a construction.
	 * There should never be a need to incorporate more fields into the hash than is incorporated
	 * here.
	 * 
	 * <p>
	 * TODO: Since refs are no longer a thing, is custom equality needed at all? Seems object
	 * identity would be sufficient.
	 * 
	 * @return the hash
	 */
	default int computeHashCode() {
		return System.identityHashCode(getModel()) * 31 + Objects.hash(getPath().toArray());
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * A friendly reminder to override
	 * 
	 * @see #doEquals(Object)
	 */
	@Override
	boolean equals(Object obj);

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * A friendly reminder to override
	 * 
	 * @see #computeHashCode()
	 */
	@Override
	int hashCode();

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Along with {@link #doEquals(Object)} and {@link #computeHashCode()}, these obey the Rule of
	 * Three, comparing first the objects' models (by name, then identity), then their paths. Like
	 * the other methods, this incorporates everything that constitutes a unique target object.
	 * There should never be a need to override or otherwise extend this.
	 */
	@Override
	default int compareTo(TargetObject that) {
		if (this == that) {
			return 0;
		}
		DebuggerObjectModel thisModel = this.getModel();
		DebuggerObjectModel thatModel = that.getModel();
		if (thisModel != thatModel) {
			if (thisModel == null) {
				return -1;
			}
			if (thatModel == null) {
				return 1;
			}
			int result = thisModel.toString().compareTo(thatModel.toString());
			if (result == 0) {
				return Integer.compare(System.identityHashCode(thisModel),
					System.identityHashCode(thatModel));
			}
			return result;
		}
		return PathComparator.KEYED.compare(this.getPath(), that.getPath());
	}

	/**
	 * Get the model to which this object belongs
	 * 
	 * @return the model
	 */
	public DebuggerObjectModel getModel();

	/**
	 * Get the path (i.e., list of names from root to this object).
	 * 
	 * <p>
	 * Every object must have a unique path. Keys in the path which are indices, i.e., which
	 * navigate the elements, are enclosed in brackets @{code []}. Keys which navigate attributes
	 * are simply the attribute name.
	 * 
	 * <p>
	 * More than just a location, the path provides a hint to the object's scope of applicability.
	 * For example, a {@link TargetMemory} attribute of a process is assumed accessible to every
	 * thread of that process, since those threads are descendants.
	 * 
	 * @return the canonical path of the object
	 */
	public List<String> getPath();

	/**
	 * Get the path joined by the given separator
	 * 
	 * <p>
	 * Note that no check is applied to guarantee the path separator does not appear in an element
	 * name. Conventionally, `.` should be the separator. The separator is omitted before indices.
	 * 
	 * @see #getPath()
	 * @param sep the path separator
	 * @return the joined path
	 */
	public default String getJoinedPath(String sep) {
		return PathUtils.toString(getPath(), sep);
	}

	/**
	 * Get the key for this object
	 * 
	 * <p>
	 * The object's key should be that assigned by the actual debugger, if applicable. If this is an
	 * element, the key should include the brackets {@code []}. If it is an attribute, it should
	 * simply be the name.
	 * 
	 * @return the key, or {@code null} if this is the root
	 */
	public default String getName() {
		return PathUtils.getKey(getPath());
	}

	/**
	 * Get the index for this object, omitting the brackets
	 * 
	 * @return they index, or {@code null} if this is the root
	 * @throws IllegalArgumentException if this object's key is not an index
	 */
	public default String getIndex() {
		return PathUtils.getIndex(getPath());
	}

	/**
	 * Check if this is the root target debug object
	 * 
	 * @return true if root, false otherwise
	 */
	public default boolean isRoot() {
		return getPath().isEmpty();
	}

	/**
	 * Get this object's canonical parent
	 * 
	 * @return the parent or {@code null} if this is the root
	 */
	public TargetObject getParent();

	/**
	 * Get an informal name identifying the type of this object
	 * 
	 * <p>
	 * This is an informal notion of type and may only be used for visual styling, logging, or other
	 * informational purposes. Scripts should not rely on this to predict behavior, but instead on
	 * {@link #getAs(Class)}, {@link #getInterfaces()}, or {@link #getSchema()}.
	 * 
	 * @return an informal name of this object's type
	 */
	public String getTypeHint();

	/**
	 * Get this object's schema
	 * 
	 * @return the schema
	 */
	public default TargetObjectSchema getSchema() {
		return EnumerableTargetObjectSchema.OBJECT;
	}

	/**
	 * Get the interfaces this object actually supports, and that the client recognizes
	 * 
	 * @implNote Proxy implementations should likely override this method.
	 * 
	 * @return the set of interfaces
	 */
	public default Collection<? extends Class<? extends TargetObject>> getInterfaces() {
		return Protected.getInterfacesOf(getClass());
	}

	/**
	 * Get the interface names this object actually supports
	 * 
	 * <p>
	 * When this object is a proxy, this set must include the names of all interfaces reported by
	 * the agent, whether or not they are recognized by the client.
	 * 
	 * @return the set of interface names
	 */
	public default Collection<String> getInterfaceNames() {
		return Protected.doGetInterfaceNamesOf(getClass());
	}

	/**
	 * Check that this object is still valid
	 * 
	 * <p>
	 * In general, an invalid object should be disposed by the user immediately on discovering it is
	 * invalid. See {@link DebuggerModelListener#invalidated(TargetObject)} for a means of reacting
	 * to object invalidation. Nevertheless, it is acceptable to access stale attributes and element
	 * keys, for informational purposes only. Implementors must reject all commands, including
	 * fetches, on an invalid object by throwing an {@link IllegalStateException}.
	 * 
	 * @return true if valid, false if invalid
	 */
	public boolean isValid();

	/**
	 * Fetch all the attributes of this object
	 * 
	 * <p>
	 * Attributes are usually keyed by a string, and the types are typically not uniform. Some
	 * attributes are primitives, while others are other target objects.
	 * 
	 * @param refresh true to invalidate all caches involved in handling this request
	 * @return a future which completes with a name-value map of attributes
	 */
	public default CompletableFuture<? extends Map<String, ?>> fetchAttributes(boolean refresh) {
		return getModel().fetchObjectAttributes(getPath(), refresh);
	}

	/**
	 * Fetch all attributes of this object, without refreshing
	 * 
	 * @see #fetchAttributes(boolean)
	 */
	public default CompletableFuture<? extends Map<String, ?>> fetchAttributes() {
		return fetchAttributes(false);
	}

	/**
	 * Fetch an attribute by name
	 * 
	 * @see #fetchAttributes()
	 * @see PathUtils#isInvocation(String)
	 * @implNote for attributes representing method invocations, the name will not likely be in the
	 *           map given by {@link #fetchAttributes()}. It will be generated upon request. The
	 *           implementation should cache the generated attribute until the attribute cache is
	 *           refreshed. TODO: Even if the method is likely to return a different value on its
	 *           next invocation? Yes, I think so. The user should manually refresh in those cases.
	 * @return a future which completes with the attribute or with {@code null} if the attribute
	 *         does not exist
	 */
	public default CompletableFuture<?> fetchAttribute(String name) {
		if (!PathUtils.isInvocation(name)) {
			return fetchAttributes().thenApply(m -> m.get(name));
		}
		Map<String, ?> cached = getCachedAttributes();
		if (cached.containsKey(name)) {
			return CompletableFuture.completedFuture(cached.get(name));
		}
		// TODO: Make a type for the invocation and parse arguments better?
		Entry<String, String> invocation = PathUtils.parseInvocation(name);
		return fetchAttribute(invocation.getKey()).thenCompose(obj -> {
			if (!(obj instanceof TargetMethod)) {
				throw new DebuggerModelTypeException(invocation.getKey() + " is not a method");
			}
			TargetMethod method = (TargetMethod) obj;
			// Just blindly invoke and let it sort it out
			return method.invoke(Map.of("arg", invocation.getValue()));
		});
	}

	/**
	 * Get the cached elements of this object
	 * 
	 * @see #getCallbackElements()
	 * @return the map of indices to element references
	 */
	public Map<String, ? extends TargetObject> getCachedElements();

	/**
	 * Get the cached elements of this object synchronized with the callbacks
	 * 
	 * <p>
	 * Whereas {@link #getCachedElements()} gets the map of elements <em>right now</em>, it's
	 * possible that view of elements is far ahead of the callback processing queue. This view is of
	 * the elements as the change callbacks have been processed so far. When accessing this from the
	 * {@link DebuggerModelListener#elementsChanged(TargetObject, Collection, Map)} callback, this
	 * map will have just had the given delta applied to it.
	 * 
	 * <p>
	 * <b>WARNING:</b>The returned map must only be accessed by the callback thread.
	 * 
	 * @return the map of indices to element references
	 */
	public Map<String, ? extends TargetObject> getCallbackElements();

	/**
	 * Fetch all the elements of this object
	 * 
	 * <p>
	 * Elements are usually keyed numerically, but allows strings for flexibility. The values are
	 * target objects, typically uniform in type, and so generally share the same attributes. The
	 * keys must omit the brackets {@code []}. Implementations should ensure that the elements are
	 * presented in order by key -- not necessarily lexicographically. To ensure clients can easily
	 * maintain correct sorting, the recommendation is to present the keys as follows: Keys should
	 * be the numeric value encoded as strings in base 10 or base 16 as appropriate, using the least
	 * number of digits needed. While rarely used, a comma-separated list of indices may be
	 * presented. Key comparators should separate the indices, attempt to convert each to a number,
	 * and then sort using the left-most indices first. Indices which cannot be converted to numbers
	 * should be sorted lexicographically. It is the implementation's responsibility to ensure all
	 * indices follow a consistent scheme.
	 * 
	 * @param refresh true to invalidate all caches involved in handling this request
	 * @return a future which completes with a index-value map of elements
	 */
	public default CompletableFuture<? extends Map<String, ? extends TargetObject>> fetchElements(
			boolean refresh) {
		return getModel().fetchObjectElements(getPath(), refresh);
	}

	/**
	 * Fetch all elements of this object, without refreshing
	 * 
	 * @see #fetchElements(boolean)
	 */
	public default CompletableFuture<? extends Map<String, ? extends TargetObject>> fetchElements() {
		return fetchElements(false);
	}

	/**
	 * Fetch an element by its index, omitting the brackets
	 * 
	 * @return a future which completes with the element or with {@code null} if it does not exist
	 */
	public default CompletableFuture<? extends TargetObject> fetchElement(String index) {
		return getModel().fetchModelObject(PathUtils.index(getPath(), index));
	}

	/**
	 * Fetch all children (elements and attributes) of this object
	 * 
	 * <p>
	 * Note that keys for element indices here must contain the brackets {@code []} to distinguish
	 * them from attribute names.
	 * 
	 * @see #fetchElements()
	 * @see #fetchAttributes()
	 * 
	 * @param refresh true to invalidate all caches involved in handling this request
	 * @return a future which completes with a name-value map of children
	 */
	public default CompletableFuture<? extends Map<String, ?>> fetchChildren(boolean refresh) {
		AsyncFence fence = new AsyncFence();
		Map<String, Object> children = new TreeMap<>(TargetObjectKeyComparator.CHILD);
		fence.include(fetchElements(refresh).thenAccept(elements -> {
			for (Map.Entry<String, ?> ent : elements.entrySet()) {
				children.put(PathUtils.makeKey(ent.getKey()), ent.getValue());
			}
		}));
		fence.include(fetchAttributes(refresh).thenAccept(children::putAll));
		return fence.ready().thenApply(__ -> children);
	}

	/**
	 * Fetch all children of this object, without refreshing
	 * 
	 * @see #fetchChildren(boolean)
	 */
	public default CompletableFuture<? extends Map<String, ?>> fetchChildren() {
		return fetchChildren(false);
	}

	/**
	 * Fetch a child (element or attribute) by key (index or name, respectively)
	 * 
	 * <p>
	 * Indices are distinguished from names by the presence or absence of brackets {@code []}. If
	 * the key is a bracket-enclosed index, this will retrieve an element, otherwise, it will
	 * retrieve an attribute.
	 * 
	 * @see #fetchAttribute(String)
	 * @see #fetchElement(String)
	 * @return a future which completes with the child
	 */
	public default CompletableFuture<?> fetchChild(String key) {
		if (PathUtils.isIndex(key)) {
			return fetchElement(PathUtils.parseIndex(key));
		}
		return fetchAttribute(key);
	}

	/**
	 * Fetch the children (elements and attributes) of this object which support the requested
	 * interface
	 * 
	 * <p>
	 * If no children support the given interface, the result is the empty set.
	 * 
	 * @param <T> the requested interface
	 * @param iface the class of the requested interface
	 * @return a future which completes with a name-value map of children supporting the given
	 *         interface
	 */
	public default <T extends TargetObject> //
	CompletableFuture<? extends Map<String, ? extends T>> fetchChildrenSupporting(Class<T> iface) {
		return fetchChildren().thenApply(m -> m.entrySet()
				.stream()
				.filter(e -> iface.isAssignableFrom(e.getValue().getClass()))
				.collect(Collectors.toMap(Entry::getKey, e -> iface.cast(e.getValue()))));
	}

	/**
	 * Fetch the value at the given sub-path from this object
	 * 
	 * <p>
	 * Extend this reference's path with the given sub-path and request that value from the same
	 * model.
	 * 
	 * @param sub the sub-path to the value
	 * @return a future which completes with the value or with {@code null} if the path does not
	 *         exist
	 */
	public default CompletableFuture<?> fetchValue(List<String> sub) {
		return getModel().fetchModelObject(PathUtils.extend(getPath(), sub));
	}

	/**
	 * @see #fetchValue(List)
	 */
	public default CompletableFuture<?> fetchValue(String... sub) {
		return fetchValue(List.of(sub));
	}

	/**
	 * Fetch the successor object at the given sub-path from this object
	 * 
	 * <p>
	 * Extend this reference's path with the given sub-path and request that object from the same
	 * model. Note unlike {@link #fetchValue(List)}, this can return objects which have been
	 * created, but not yet added to the model.
	 * 
	 * @param sub the sub-path to the successor
	 * @return a future which completes with the object or with {@code null} if it does not exist
	 */
	public default CompletableFuture<? extends TargetObject> fetchSuccessor(List<String> sub) {
		return getModel().fetchModelObject(PathUtils.extend(getPath(), sub));
	}

	/**
	 * @see #fetchSuccessor(List)
	 */
	public default CompletableFuture<? extends TargetObject> fetchSuccessor(String... sub) {
		return fetchSuccessor(List.of(sub));
	}

	/**
	 * Get the cached successor of this object
	 * 
	 * <p>
	 * Extend this object's path with the given sub-path, and search the model's cache for it.
	 * 
	 * @param sub the sub-path to the successor
	 * @return the successor or {@code null} if it doesn't exist in the cache
	 */
	public default TargetObject getSuccessor(List<String> sub) {
		return getModel().getModelObject(PathUtils.extend(getPath(), sub));
	}

	/**
	 * @see #getSuccessor(List)
	 */
	public default TargetObject getSuccessor(String... sub) {
		return getSuccessor(List.of(sub));
	}

	/**
	 * Fetch the attributes of a successor to this object
	 * 
	 * @param sub the sub-path to the successor whose attributes to list
	 * @return a future map of attributes
	 */
	public default CompletableFuture<? extends Map<String, ?>> fetchSubAttributes(
			List<String> sub) {
		return getModel().fetchObjectAttributes(PathUtils.extend(getPath(), sub));
	}

	/**
	 * @see #fetchSubAttributes(List)
	 */
	public default CompletableFuture<? extends Map<String, ?>> fetchSubAttributes(String... sub) {
		return fetchSubAttributes(List.of(sub));
	}

	/**
	 * Fetch the attribute of a successor object, using a sub-path from this object
	 * 
	 * <p>
	 * Extends this object's path with the given sub-path and request that attribute from the same
	 * model.
	 * 
	 * @param sub the sub-path to the attribute
	 * @return a future which completes with the value or with {@code null} if it does not exist
	 */
	public default CompletableFuture<?> fetchSubAttribute(List<String> sub) {
		return getModel().fetchObjectAttribute(PathUtils.extend(getPath(), sub));
	}

	/**
	 * @see #fetchSubAttribute(List)
	 */
	public default CompletableFuture<?> fetchSubAttribute(String... sub) {
		return fetchSubAttribute(List.of(sub));
	}

	/**
	 * Fetch the elements of a successor to this object
	 * 
	 * @param sub the sub-path to the successor whose elements to list
	 * @return a future map of elements
	 */
	public default CompletableFuture<? extends Map<String, ? extends TargetObject>> fetchSubElements(
			List<String> sub) {
		return getModel().fetchObjectElements(PathUtils.extend(getPath(), sub));
	}

	/**
	 * @see #fetchSubElements(List)
	 */
	public default CompletableFuture<? extends Map<String, ? extends TargetObject>> fetchSubElements(
			String... sub) {
		return fetchSubElements(List.of(sub));
	}

	/**
	 * Get a description of the object, suitable for display in the UI
	 * 
	 * @return the display description
	 */
	@TargetAttributeType(name = DISPLAY_ATTRIBUTE_NAME, hidden = true)
	public default String getDisplay() {
		return getTypedAttributeNowByName(DISPLAY_ATTRIBUTE_NAME, String.class, getName());
	}

	/**
	 * Get a brief description of the object, suitable for display in the UI
	 * 
	 * @return the display description
	 */
	@TargetAttributeType(name = SHORT_DISPLAY_ATTRIBUTE_NAME, hidden = true)
	public default String getShortDisplay() {
		return getTypedAttributeNowByName(SHORT_DISPLAY_ATTRIBUTE_NAME, String.class, getDisplay());
	}

	/**
	 * Get a hint to the "kind" of object this represents
	 * 
	 * <p>
	 * This is useful when the native debugger presents a comparable tree-like model. If this object
	 * is simply proxying an object from that model, and that model provides additional type
	 * information that would not otherwise be encoded in this model.
	 * 
	 * @return the kind of the object
	 */
	@TargetAttributeType(name = KIND_ATTRIBUTE_NAME, fixed = true, hidden = true)
	public default String getKind() {
		return getTypedAttributeNowByName(KIND_ATTRIBUTE_NAME, String.class, getDisplay());
	}

	/**
	 * A custom ordinal for positioning this item on screen
	 * 
	 * <p>
	 * Ordinarily, children are ordered by key, attributes followed by elements. The built-in
	 * comparator does a decent job ordering them, so long as indices keep a consistent format among
	 * siblings. In some cases, however, especially with query-style methods, the same objects (and
	 * thus keys) need to be presented with an alternative ordering. This attribute can be used by
	 * model implementations to recommend an alternative ordering, where siblings are instead sorted
	 * according to this ordinal.
	 * 
	 * @return the recommended display position for this element
	 */
	@TargetAttributeType(name = ORDER_ATTRIBUTE_NAME, hidden = true)
	public default Integer getOrder() {
		return getTypedAttributeNowByName(ORDER_ATTRIBUTE_NAME, Integer.class, null);
	}

	/**
	 * For values, check if it was "recently" modified
	 * 
	 * <p>
	 * TODO: This should probably be moved to a new {@code TargetObject} interface.
	 * 
	 * <p>
	 * "Recently" generally means since (or as a result of ) the last event affecting a target in
	 * the same scope. This is mostly used as a UI hint, to bring the user's attention to modified
	 * values.
	 * 
	 * @return true if modified, false if not
	 */
	@TargetAttributeType(name = MODIFIED_ATTRIBUTE_NAME, hidden = true)
	public default Boolean isModified() {
		return getTypedAttributeNowByName(MODIFIED_ATTRIBUTE_NAME, Boolean.class, null);
	}

	/**
	 * For values, get the type of the value
	 * 
	 * <p>
	 * TODO: This should probably be moved to a new {@code TargetObject} interface. How does this
	 * differ from "kind" when both are present? Can this be a {@link TargetNamedDataType} instead?
	 * Though, I suppose that would imply the object is a value in the target execution state, e.g.,
	 * a register, variable, field, etc.
	 * 
	 * @return the name of the type
	 */
	@TargetAttributeType(name = TYPE_ATTRIBUTE_NAME, hidden = true)
	public default String getType() {
		return getTypedAttributeNowByName(TYPE_ATTRIBUTE_NAME, String.class, null);
	}

	/**
	 * For values, get the actual value
	 * 
	 * <p>
	 * TODO: This should probably be moved to a new {@code TargetObject} interface.
	 * 
	 * @return the value
	 */
	@TargetAttributeType(name = VALUE_ATTRIBUTE_NAME, hidden = true)
	public default Object getValue() {
		return getCachedAttribute(VALUE_ATTRIBUTE_NAME);
	}

	/**
	 * Refresh the children of this object
	 * 
	 * <p>
	 * The default fetch implementations follow the prescription of
	 * {@link TargetObjectSchema#getElementResyncMode()} and
	 * {@link TargetObjectSchema#getAttributeResyncMode()}. The client may call this method when,
	 * for unknown reasons, the respective cache(s) are out of sync with the target debugger. Such
	 * circumstances indicate an implementation error, but this method may provide a means to
	 * recover. When a {@code refresh} parameter is set, the model should be aggressive in updating
	 * its respective cache(s).
	 * 
	 * @param refreshAttributes ask the model to refresh attributes, querying the debugger if needed
	 * @param refreshElements as the model to refresh elements, querying the debugger if needed
	 * @return a future which completes when the children are updated.
	 */
	CompletableFuture<Void> resync(boolean refreshAttributes, boolean refreshElements);

	/**
	 * Refresh the elements of this object
	 * 
	 * @return a future which completes when the children are updated.
	 */
	default CompletableFuture<Void> resync() {
		return resync(false, true);
	}

	/**
	 * Get the (usually opaque) identifier that the underlying connection uses for this object
	 * 
	 * <p>
	 * The opaque identifier should implement proper {@link Object#hashCode()} and
	 * {@link Object#equals(Object)}, so that paired with the model, it forms a unique key for this
	 * target object. It should also implement {@link Object#toString()}; however, it is for
	 * debugging or informational purposes only. It is common for this identifier to be the object's
	 * path.
	 * 
	 * @return the identifier
	 */
	public Object getProtocolID();

	/**
	 * Get this same object, cast to the requested interface, if supported
	 * 
	 * <p>
	 * This differs from Java-style casting in two ways: 1) The receiver cannot be {@code null}, and
	 * 2) It throws a different exception. Server-side proxy implementations must marshall the
	 * {@link DebuggerModelTypeException} to the client; whereas, for {@link ClassCastException}, it
	 * may simply report "Server-side Error," because that exception may have been thrown by an
	 * unrelated cast.
	 * 
	 * @param <T> the requested interface
	 * @param iface the class of the requested interface
	 * @return the same object, cast to the interface
	 * @throws DebuggerModelTypeException if the interface is not supported by this object
	 */
	public default <T extends TargetObject> T as(Class<T> iface) {
		return DebuggerObjectModel.requireIface(iface, this, getPath());
	}

	/**
	 * Get the cached attributes of this object
	 * 
	 * @see #getCallbackAttributes()
	 * @return the cached name-value map of attributes
	 */
	public Map<String, ?> getCachedAttributes();

	/**
	 * Get the cached attributes of this object synchronized with the callbacks
	 * 
	 * <p>
	 * Whereas {@link #getCachedAttributes()} gets the map of attributes <em>right now</em>, it's
	 * possible that view of attributes if far ahead of the callback processing queue. This view is
	 * of the attributes as the change callbacks have been processed so far. When accessing this
	 * from the {@link DebuggerModelListener#attributesChanged(TargetObject, Collection, Map)}
	 * callback, this map will have just had the given delta applied to it.
	 * 
	 * <p>
	 * <b>WARNING:</b>The returned map must only be accessed by the callback thread.
	 * 
	 * @return the cached name-value map of attributes
	 */
	public Map<String, ?> getCallbackAttributes();

	/**
	 * Get the named attribute from the cache
	 * 
	 * @param name the name of the attribute
	 * @return the value
	 */
	public default Object getCachedAttribute(String name) {
		return getCachedAttributes().get(name);
	}

	/**
	 * Cast the named attribute to the given type, if possible
	 * 
	 * <p>
	 * If the attribute value is {@code null} or cannot be cast to the given type, the fallback
	 * value is returned.
	 * 
	 * @param <T> the expected type of the attribute
	 * @param name the name of the attribute
	 * @param cls the class giving the expected type
	 * @param fallback the fallback value
	 * @return the value casted to the expected type, or the fallback value
	 */
	public default <T> T getTypedAttributeNowByName(String name, Class<T> cls, T fallback) {
		Object obj = getCachedAttribute(name);
		TargetObjectSchema schema = getSchema();
		boolean required = schema.getAttributeSchema(name).isRequired();
		return ValueUtils.expectType(obj, cls, this, name, fallback, required);
	}

	/**
	 * Invalidate caches associated with this object, other than those for cached children
	 * 
	 * <p>
	 * Some objects, e.g., memories and register banks, may have caches to reduce requests and
	 * callbacks. This method should clear such caches, if applicable, but <em>must not</em> clear
	 * caches of elements or attributes.
	 * 
	 * <p>
	 * In the case of a proxy, the proxy must invalidate all local caches, as well as request the
	 * remote object invalidate its caches. In this way, all caches between the user and the actual
	 * data, no matter where they are hosted, are invalidated.
	 * 
	 * @return a future which completes when the caches are invalidated
	 */
	public default CompletableFuture<Void> invalidateCaches() {
		return AsyncUtils.NIL;
	}

	/**
	 * Listen for object events
	 * 
	 * <p>
	 * The client must maintain a strong reference to the listener. To allow stale listeners to be
	 * garbage collected, the implementation should use weak or soft references. That said, the
	 * client should not rely on the implementation to garbage collect its listeners. All unneeded
	 * listeners should be removed using {@link #removeListener(TargetObjectListener)}. The
	 * exception is when an object is invalidated. The client may safely neglect removing any
	 * listeners it registered with that object. If the object does not keep listeners, i.e., it
	 * produces no events, this method may do nothing.
	 * 
	 * <p>
	 * Clients ought to listen on the model instead of specific objects, especially since an object
	 * may emit events immediately after its creation, but before the client has a chance to add a
	 * listener. Worse yet, the object could be invalidated before the client can retrieve its
	 * children. Listening on the model ensures the reception of a complete log of events.
	 * 
	 * @see DebuggerObjectModel#addModelListener(DebuggerModelListener)
	 * @param l the listener
	 */
	public default void addListener(DebuggerModelListener l) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Remove a listener
	 * 
	 * <p>
	 * If the given listener is not registered with this object, this method does nothing.
	 * 
	 * @param l the listener
	 */
	public default void removeListener(DebuggerModelListener l) {
		throw new UnsupportedOperationException();
	}
}
