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
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import ghidra.async.AsyncFence;
import ghidra.async.AsyncUtils;
import ghidra.dbg.*;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.attributes.TypedTargetObjectRef;
import ghidra.dbg.error.DebuggerModelTypeException;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.AttributeSchema;
import ghidra.dbg.util.PathUtils;
import ghidra.dbg.util.PathUtils.TargetObjectKeyComparator;
import ghidra.dbg.util.ValueUtils;
import ghidra.lifecycle.Internal;
import ghidra.util.Msg;

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
 * Each element in the path identifies an index (if the child is an element) or a name (if the child
 * is an attribute). It is the implementation's responsibility to ensure each object's path
 * correctly identifies that same object in the model directory. The root has the empty path. Every
 * object must have a unique path; thus, every object must have a unique name among its sibling.
 * 
 * <p>
 * The objects are arranged in a directory with links permitted. Links come in the form of
 * object-valued attributes where the attribute path is not its value's path. Thus, the overall
 * structure remains a tree, but by resolving links, the model may be treated as a directed graph,
 * likely containing cycles. See {@link PathUtils#isLink(List, String, List)}.
 * 
 * <p>
 * The implementation must guarantee that distinct {@link TargetObject}s from the same model do not
 * refer to the same path. That is, checking for object identity is sufficient to check that two
 * variables refer to the same object. It is recommended that client-side implementations use a
 * weak-valued map of paths to cached target objects.
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
 * recursively if the child attributes are also marked with {@link TargetAggregate}.</li>
 * <li><b>Ancestry:</b> Apply these same steps to the object's (canonical) parent, recursively.</li>
 * </ol>
 * 
 * <p>
 * For some situations, exactly one object is required. In that case, take the first obtained by
 * applying the above rules. In other situations, multiple objects may be acceptable. Again, apply
 * the rules until a sufficient collection of objects is obtained. If an object is in conflict with
 * another, take the first encountered. This situation may be appropriate if, e.g., multiple target
 * memories present disjoint regions. There should not be conflicts among sibling. If there are,
 * then either the model or the query is not sound. The order sibling are considered should not
 * matter. These rules are incubating and are implemented in {@link DebugModelConventions}.
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
public interface TargetObject extends TargetObjectRef {

	Set<Class<? extends TargetObject>> ALL_INTERFACES = Set.of(
		TargetAccessConditioned.class,
		TargetAggregate.class,
		TargetAttachable.class,
		TargetAttacher.class,
		TargetBreakpointContainer.class,
		TargetBreakpointSpec.class,
		TargetDataTypeMember.class,
		TargetDataTypeNamespace.class,
		TargetDeletable.class,
		TargetDetachable.class,
		TargetBreakpointLocation.class,
		TargetEnvironment.class,
		TargetEventScope.class,
		TargetExecutionStateful.class,
		TargetFocusScope.class,
		TargetInterpreter.class,
		TargetInterruptible.class,
		TargetKillable.class,
		TargetLauncher.class,
		TargetMethod.class,
		TargetMemory.class,
		TargetMemoryRegion.class,
		TargetModule.class,
		TargetModuleContainer.class,
		TargetNamedDataType.class,
		TargetProcess.class,
		TargetRegister.class,
		TargetRegisterBank.class,
		TargetRegisterContainer.class,
		TargetResumable.class,
		TargetSection.class,
		TargetStack.class,
		TargetStackFrame.class,
		TargetSteppable.class,
		TargetSymbol.class,
		TargetSymbolNamespace.class,
		TargetThread.class);
	Map<String, Class<? extends TargetObject>> INTERFACES_BY_NAME = initInterfacesByName();

	/**
	 * Initializer for {@link #INTERFACES_BY_NAME}
	 * 
	 * @return interfaces indexed by name
	 */
	@Internal
	static Map<String, Class<? extends TargetObject>> initInterfacesByName() {
		return ALL_INTERFACES.stream()
				.collect(Collectors.toUnmodifiableMap(
					DebuggerObjectModel::requireIfaceName, i -> i));
	}

	static List<Class<? extends TargetObject>> getInterfacesByName(
			Collection<String> names) {
		return names.stream()
				.filter(INTERFACES_BY_NAME::containsKey)
				.map(INTERFACES_BY_NAME::get)
				.collect(Collectors.toList());
	}

	@Deprecated
	String PREFIX_INVISIBLE = "_";

	String DISPLAY_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "display";
	String SHORT_DISPLAY_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "short_display";
	String KIND_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "kind";
	String UPDATE_MODE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "update_mode";
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

		protected static Collection<String> getInterfaceNamesOf(Class<? extends TargetObject> cls) {
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

	enum TargetUpdateMode {
		/**
		 * The object's elements are kept up to date via unsolicited push notifications / callbacks.
		 * 
		 * <p>
		 * This is the default.
		 */
		UNSOLICITED,
		/**
		 * The object's elements are only updated when requested.
		 * 
		 * <p>
		 * The request may still generate push notifications / callbacks if others are listening
		 */
		SOLICITED,
		/**
		 * The object's elements will not change.
		 * 
		 * <p>
		 * This is a promise made by the model implementation. Once the {@code update_mode}
		 * attribute has this value, it should never be changed back. Note that other attributes of
		 * this object are still expected to be kept up to date, if they change.
		 */
		FIXED;
	}

	/**
	 * Get an informal name identify the type of this object.
	 * 
	 * <p>
	 * This is an informal notion of type and may only be used for visual styling, logging, or other
	 * informational purposes. Scripts should not rely on this to predict behavior, but instead on
	 * {@link #getAs(Class)} or {@link #getInterfaces()};
	 * 
	 * @return an informal name of this object's type
	 */
	public String getTypeHint();

	/**
	 * Get this object's schema.
	 * 
	 * @return the schema
	 */
	public default TargetObjectSchema getSchema() {
		return EnumerableTargetObjectSchema.OBJECT;
	}

	/**
	 * Get the interfaces this object actually supports, and that the client recognizes.
	 * 
	 * @implNote Proxy implementations should likely override this method.
	 * 
	 * @return the set of interfaces
	 */
	public default Collection<? extends Class<? extends TargetObject>> getInterfaces() {
		return Protected.getInterfacesOf(getClass());
	}

	/**
	 * Get the interface names this object actually supports.
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
	 * invalid. See {@link TargetObjectListener#invalidated(TargetObject)} for a means of reacting
	 * to object invalidation. Nevertheless, it is acceptable to access stale attributes and element
	 * keys, for informational purposes only. Implementors must reject all commands, including
	 * non-cached gets, on an invalid object by throwing an {@link IllegalStateException}.
	 * 
	 * @return true if valid, false if invalid
	 */
	public boolean isValid();

	/**
	 * Fetch the canonical parent of this object
	 * 
	 * <p>
	 * Note that if this is the root, a future is still returned, but it will complete with
	 * {@code null}.
	 * 
	 * @return a future which completes with the parent object
	 */
	default CompletableFuture<? extends TargetObject> fetchParent() {
		TargetObjectRef parent = getParent();
		if (parent == null) {
			return AsyncUtils.nil();
		}
		return parent.fetch();
	}

	/**
	 * Get the cached elements of this object
	 * 
	 * <p>
	 * Note these are cached elements, and there's no requirement on the model's part to keep this
	 * cache up to date (unlike attributes). Thus, the indices (keys) in the returned map may be
	 * out-of-date.
	 * 
	 * <p>
	 * Note that this method is not required to provide objects, but only object references. Local
	 * implementations, and clients having the appropriate proxies cached may present some, all, or
	 * none of the entries with actual objects. Users should NEVER depend on this being the case,
	 * however. Always call {@link TargetObjectRef#fetch()}, or use {@link #fetchElements} instead,
	 * to guarantee the actual objects are presented.
	 * 
	 * @return the map of indices to element references
	 */
	public Map<String, ? extends TargetObjectRef> getCachedElements();

	/**
	 * Get a description of the object, suitable for display in the UI.
	 * 
	 * @return the display description
	 */
	@TargetAttributeType(name = DISPLAY_ATTRIBUTE_NAME, hidden = true)
	public default String getDisplay() {
		return getTypedAttributeNowByName(DISPLAY_ATTRIBUTE_NAME, String.class, getName());
	}

	/**
	 * Get a brief description of the object, suitable for display in the UI.
	 * 
	 * @return the display description
	 */
	@TargetAttributeType(name = SHORT_DISPLAY_ATTRIBUTE_NAME, hidden = true)
	public default String getShortDisplay() {
		return getTypedAttributeNowByName(SHORT_DISPLAY_ATTRIBUTE_NAME, String.class, getDisplay());
	}

	/**
	 * Get a hint to the "kind" of object this represents.
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
	 * Get the element update mode for this object
	 * 
	 * <p>
	 * The update mode informs the client's caching implementation. If set to
	 * {@link TargetUpdateMode#UNSOLICITED}, the client will assume its cache is kept up to date via
	 * listener callbacks, and may avoid querying for the object's elements. If set to
	 * {@link TargetUpdateMode#FIXED}, the client can optionally remove its listener for element
	 * changes but still assume its cache is up to date, since the object's elements are no longer
	 * changing. If set to {@link TargetUpdateMode#SOLICITED}, the client must re-validate its cache
	 * whenever the elements are requested. It is still recommended that the client listen for
	 * element changes, since the local cache may be updated (resulting in callbacks) when handling
	 * requests from another client.
	 * 
	 * <p>
	 * IMPORTANT: Update mode does not apply to attributes. Except in rare circumstances, the model
	 * must keep an object's attributes up to date.
	 * 
	 * @return the update mode
	 */
	@TargetAttributeType(name = UPDATE_MODE_ATTRIBUTE_NAME, hidden = true)
	public default TargetUpdateMode getUpdateMode() {
		return getTypedAttributeNowByName(UPDATE_MODE_ATTRIBUTE_NAME, TargetUpdateMode.class,
			TargetUpdateMode.UNSOLICITED);
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
	 * TODO: This should probably be moved to a new {@code TargetType} interface.
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
	 * TODO: This should probably be moved to a new {@code TargetType} interface. How does this
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
	 * TODO: This should probably be moved to a new {@code TargetType} interface.
	 * 
	 * @return the value
	 */
	@TargetAttributeType(name = VALUE_ATTRIBUTE_NAME, hidden = true)
	public default Object getValue() {
		return getCachedAttribute(VALUE_ATTRIBUTE_NAME);
	}

	@Override
	default CompletableFuture<? extends TargetObject> fetch() {
		return CompletableFuture.completedFuture(this);
	}

	/**
	 * Get the (usually opaque) identifier that the underlying connection uses for this object
	 * 
	 * <p>
	 * The opaque identifier should implement proper {@link Object#hashCode()} and
	 * {@link Object#equals(Object)}, so that paired with the client, it forms a unique key for this
	 * target object. It should also implement {@link Object#toString()}; however, it is for
	 * debugging or informational purposes only. It is common for this identifier to be the object's
	 * path.
	 * 
	 * @return the identifier
	 */
	public Object getProtocolID();

	/**
	 * Get this same object, cast to the requested interface, if supported.
	 * 
	 * @param <T> the requested interface
	 * @param iface the class of the requested interface
	 * @return the same object, cast to the interface
	 * @throws DebuggerModelTypeException if the interface is not supported by this object
	 */
	@Override
	public default <T extends TypedTargetObject<T>> T as(Class<T> iface) {
		return DebuggerObjectModel.requireIface(iface, this, getPath());
	}

	/**
	 * Get the cached attributes of this object
	 * 
	 * <p>
	 * While this technically only returns "cached" attributes, the model should be pushing
	 * attribute updates to the object automatically. Thus, the names (keys) and values in the
	 * returned map should be up-to-date.
	 * 
	 * <p>
	 * Note that object-valued attributes are only guaranteed to be a {@link TargetObjectRef}. Local
	 * implementations, and clients having the appropriate proxies cached may present some, all, or
	 * none of the object-valued attributes with the actual object. Users should NEVER depend on
	 * this being the case, however. Always call {@link TargetObjectRef#fetch()}, or use
	 * {@link #fetchAttributes()} instead, to guarantee the actual objects are presented.
	 * 
	 * @return the cached name-value map of attributes
	 */
	public Map<String, ?> getCachedAttributes();

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
		AttributeSchema as = getSchema().getAttributeSchema(name);
		Object obj = getCachedAttribute(name);
		return ValueUtils.expectType(obj, cls, this, name, fallback, as.isRequired());
	}

	/**
	 * Cast the named object-reference attribute to the given type, if possible
	 * 
	 * <p>
	 * In addition to casting the attribute to an object reference, if possible, this wraps that
	 * reference in {@link TypedTargetObjectRef}, which if fetched, casts the object to the required
	 * type, if possible.
	 * 
	 * @param <T> the expected type of the object
	 * @param name the name of the attribute
	 * @param cls the class giving the expected type
	 * @param fallback the fallback object
	 * @return the typed object reference
	 */
	public default <T extends TypedTargetObject<T>> TypedTargetObjectRef<T> getTypedRefAttributeNowByName(
			String name, Class<T> cls, T fallback) {
		TargetObjectRef ref = getTypedAttributeNowByName(name, TargetObjectRef.class, null);
		return ref == null ? fallback : TypedTargetObjectRef.casting(cls, ref);
	}

	/**
	 * Invalidate caches associated with this object, other than those for cached children
	 * 
	 * <p>
	 * Some objects, e.g., memories and register banks, may have caches to reduce requests and
	 * callbacks. This method should clear such caches, if applicable, but <em>should not</em> clear
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
	 * The caller must maintain a strong reference to the listener. To allow stale listeners to be
	 * garbage collected, the implementation should use weak or soft references. That said, the
	 * client user must not rely on the implementation to garbage collect its listeners. All
	 * unneeded listeners should be removed using {@link #removeListener(TargetObjectListener)}. The
	 * exception is when an object is destroyed. The user may safely neglect removing any listeners
	 * it registered with that object. If the object does not keep listeners, i.e., it produces no
	 * events, this method may do nothing.
	 * 
	 * @param l the listener
	 */
	public default void addListener(TargetObjectListener l) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Remove a listener
	 * 
	 * <p>
	 * If the given listener is not registered with this object, this method should do nothing.
	 * 
	 * @param l the listener
	 */
	public default void removeListener(TargetObjectListener l) {
		throw new UnsupportedOperationException();
	}

	public interface TargetObjectListener {
		/**
		 * The object's display string has changed
		 * 
		 * @param object the object
		 * @param display the new display string
		 */
		default void displayChanged(TargetObject object, String display) {
		}

		/**
		 * The object is no longer valid
		 * 
		 * <p>
		 * This should be the final callback ever issued for this object. Invalidation of an object
		 * implies invalidation of all its successors; nevertheless, the implementation MUST
		 * explicitly invoke this callback for those successors in preorder. Users need only listen
		 * for invalidation by installing a listener on the object of interest. However, a user must
		 * be able to ignore invalidation events on an object it has already removed and/or
		 * invalidated. For models that are managed by a client connection, disconnecting or
		 * otherwise terminating the session should invalidate the root, and thus every object must
		 * receive this callback.
		 * 
		 * <p>
		 * If an invalidated object is replaced (i.e., a new object with the same path is added to
		 * the model), the implementation must be careful to issue all invalidations related to the
		 * removed object before the replacement is added, so that delayed invalidations are not
		 * mistakenly applied to the replacement or its successors.
		 * 
		 * @param object the now-invalid object
		 * @param reason an informational, human-consumable reason, if applicable
		 */
		default void invalidated(TargetObject object, String reason) {
		}

		/**
		 * The object's elements changed
		 * 
		 * @param parent the object whose children changed
		 * @param removed the list of removed children
		 * @param added a map of indices to new children references
		 */
		default void elementsChanged(TargetObject parent, Collection<String> removed,
				Map<String, ? extends TargetObjectRef> added) {
		}

		/**
		 * The object's attributes changed
		 * 
		 * <p>
		 * In the case of an object-valued attribute, changes to that object do not constitute a
		 * changed attribute. The attribute is considered changed only when that attribute is
		 * assigned to a completely different object.
		 * 
		 * @param parent the object whose attributes changed
		 * @param removed the list of removed attributes
		 * @param added a map of names to new/changed attributes
		 */
		default void attributesChanged(TargetObject parent, Collection<String> removed,
				Map<String, ?> added) {
		}

		/**
		 * The model has requested the user invalidate caches associated with this object
		 * 
		 * <p>
		 * For objects with methods exposing contents which transcend elements and attributes (e.g.,
		 * memory contents), this callback requests that any caches associated with that content be
		 * invalidated. Most notably, this usually occurs when an object (e.g., thread) enters the
		 * {@link TargetExecutionState#RUNNING} state, to inform proxies that they should invalidate
		 * their memory and register caches. In most cases, users need not worry about this
		 * callback. Protocol implementations that use the model, however, should forward this
		 * request to the client implementation.
		 * 
		 * <p>
		 * Note caches of elements and attributes are not affected by this callback. See
		 * {@link TargetObject#invalidateCaches()}.
		 * 
		 * @param object the object whose caches must be invalidated
		 */
		default void invalidateCacheRequested(TargetObject object) {
		}
	}

	/**
	 * An adapter which automatically gets new children from the model
	 */
	public interface TargetObjectFetchingListener extends TargetObjectListener {
		@Override
		default void elementsChanged(TargetObject parent, Collection<String> removed,
				Map<String, ? extends TargetObjectRef> added) {
			AsyncFence fence = new AsyncFence();
			Map<String, TargetObject> objects = new TreeMap<>(TargetObjectKeyComparator.ELEMENT);
			for (Map.Entry<String, ? extends TargetObjectRef> ent : added.entrySet()) {
				fence.include(ent.getValue().fetch().thenAccept(o -> {
					synchronized (objects) {
						objects.put(ent.getKey(), o);
					}
				}).exceptionally(e -> {
					Msg.error(this, "Could not retrieve an object just added: " + ent.getValue());
					return null;
				}));
			}
			fence.ready().thenAccept(__ -> {
				elementsChangedObjects(parent, removed, objects);
			}).exceptionally(e -> {
				Msg.error(this, "Error in callback to elementsChangedObjects: ", e);
				return null;
			});
		}

		@Override
		default void attributesChanged(TargetObject parent, Collection<String> removed,
				Map<String, ?> added) {
			AsyncFence fence = new AsyncFence();
			Map<String, Object> attributes = new TreeMap<>(TargetObjectKeyComparator.ATTRIBUTE);
			for (Map.Entry<String, ?> ent : added.entrySet()) {
				Object val = ent.getValue();
				if (!(val instanceof TargetObjectRef)) {
					attributes.put(ent.getKey(), val);
					continue;
				}
				// NOTE: if it's the actual object, it should already be completed.
				TargetObjectRef ref = (TargetObjectRef) val;
				if (PathUtils.isLink(parent.getPath(), ent.getKey(), ref.getPath())) {
					attributes.put(ent.getKey(), val);
					continue;
				}
				fence.include(ref.fetch().thenAccept(o -> {
					synchronized (attributes) {
						attributes.put(ent.getKey(), o);
					}
				}).exceptionally(e -> {
					Msg.error(this, "Could not retrieve an object just added: " + ent.getValue());
					return null;
				}));
			}
			fence.ready().thenAccept(__ -> {
				attributesChangedObjects(parent, removed, attributes);
			}).exceptionally(e -> {
				Msg.error(this, "Error in callback to attributesChangedObjects: ", e);
				return null;
			});
		}

		/**
		 * The object's children changed
		 * 
		 * <p>
		 * In this adapter, the map contains the actual objects. In the case of client proxies, it
		 * is the protocol implementation's responsibility to ensure that object attributes are kept
		 * up to date.
		 * 
		 * @param parent the object whose children changed
		 * @param removed the list of removed children
		 * @param added a map of indices to new children
		 * @see #elementsChanged(TargetObject, List, Map)
		 */
		default void elementsChangedObjects(TargetObject parent, Collection<String> removed,
				Map<String, ? extends TargetObject> added) {
		};

		/**
		 * The object's attributes changed
		 * 
		 * <p>
		 * In this adapter, where an attribute has an object value, the map contains the retrieved
		 * object. In the case of client proxies, it is the protocol implementation's responsibility
		 * to ensure that object attributes are kept up to date.
		 * 
		 * @param parent the object whose attributes changed
		 * @param removed the list of removed attributes
		 * @param added a map of names to new/changed attributes
		 * @see #attributesChanged(TargetObject, List, Map)
		 */
		default void attributesChangedObjects(TargetObject parent, Collection<String> removed,
				Map<String, ?> added) {
		};
	}
}
