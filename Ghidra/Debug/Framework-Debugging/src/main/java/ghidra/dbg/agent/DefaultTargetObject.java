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
package ghidra.dbg.agent;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.util.CollectionUtils.Delta;
import ghidra.util.Msg;

/**
 * A default implementation of {@link TargetObject} suitable for cases where the implementation
 * defines the model structure.
 *
 * @see AbstractTargetObject
 * @param <E> the type of child elements
 * @param <P> the type of the parent
 */
public class DefaultTargetObject<E extends TargetObject, P extends TargetObject>
		extends AbstractTargetObject<P> {

	/** Note modifying this directly subverts notifications */
	protected final Map<String, E> elements = new HashMap<>();
	protected final Map<String, E> cbElements = new HashMap<>();
	protected final Map<String, E> roCbElements = Collections.unmodifiableMap(cbElements);
	protected CompletableFuture<Void> curElemsRequest;

	/** Note modifying this directly subverts notifications */
	protected final Map<String, Object> attributes = new HashMap<>();
	protected final Map<String, Object> cbAttributes = new HashMap<>();
	protected final Map<String, Object> roCbAttributes = Collections.unmodifiableMap(cbAttributes);
	protected CompletableFuture<Void> curAttrsRequest;

	/**
	 * Construct a new default target object whose schema is derived from the parent
	 * 
	 * @see #DefaultTargetObject(DebuggerObjectModel, TargetObject, String, String,
	 *      TargetObjectSchema)
	 * @param model the model to which the object belongs
	 * @param parent the (non-null) parent of this object
	 * @param key the key (attribute name or element index) of this object
	 * @param typeHint the type hint for this object
	 */
	public DefaultTargetObject(AbstractDebuggerObjectModel model, P parent, String key,
			String typeHint) {
		this(model, parent, key, typeHint, parent.getSchema().getChildSchema(key));
	}

	/**
	 * Construct a new default target object
	 * 
	 * <p>
	 * Note, this will automatically construct the appropriate path for this object. The implementor
	 * should not create two objects with the same path. In that event, collisions will probably
	 * favor the second, but in general, it produces undefined behavior. Also, this does not add the
	 * new object to its parent. The implementor must do that. This affords an opportunity to
	 * populate this object's elements and attributes before it is added to the model.
	 * 
	 * <p>
	 * The default update mode is set to {@link TargetUpdateMode#UNSOLICITED}, which implies the
	 * implementation will keep the elements cache in sync with the debugger. It is preferable to
	 * initialize the cache (via {@link #changeElements(Collection, Collection, String)}) before
	 * adding this object to the model. If it is infeasible to keep this object's elements cache
	 * updated, the implementor MUST set the update mode to {@link TargetUpdateMode#SOLICITED}.
	 * Ideally, for objects whose elements will never change, the mode can be set to
	 * {@link TargetUpdateMode#FIXED} immediately after populating the elements.
	 * 
	 * @param model the model to which the object belongs
	 * @param parent the parent of this object
	 * @param key the key (attribute name or element index) of this object
	 * @param typeHint the type hint for this object
	 * @param schema the schema of this object
	 */
	public DefaultTargetObject(AbstractDebuggerObjectModel model, P parent, String key,
			String typeHint, TargetObjectSchema schema) {
		this(THIS_FACTORY, null, model, parent, key, typeHint, schema);
	}

	/**
	 * Construct a new (delegate) default target object
	 * 
	 * <p>
	 * This behaves similarly to
	 * {@link #DefaultTargetObject(AbstractDebuggerObjectModel, TargetObject, String, String, TargetObjectSchema)}
	 * when this object is meant to be the delegate of a proxy. The {@code proxyFactory} and
	 * {@code proxyInfo} arguments are necessary to sidestep Java's insistence that the
	 * super-constructor be invoked first. It allows information to be passed straight to the
	 * factory. Using method overrides doesn't work, because the factory method gets called during
	 * construction, before extensions have a chance to initialize fields, on which the proxy
	 * inevitably depends.
	 * 
	 * @param proxyFactory a factory to create the proxy, invoked in the super constructor
	 * @param proxyInfo additional information passed to the proxy factory
	 * @param model the model to which the object belongs
	 * @param parent the parent of this object
	 * @param key the key (attribute name or element index) of this object
	 * @param typeHint the type hint for this object
	 * @param schema the schema of this object
	 */
	public <I> DefaultTargetObject(ProxyFactory<I> proxyFactory, I proxyInfo,
			AbstractDebuggerObjectModel model, P parent, String key, String typeHint,
			TargetObjectSchema schema) {
		super(proxyFactory, proxyInfo, model, parent, key, typeHint, schema);
		changeAttributes(List.of(), List.of(),
			Map.ofEntries(Map.entry(DISPLAY_ATTRIBUTE_NAME, key == null ? "<root>" : key)),
			"Default");
	}

	public <I> DefaultTargetObject(ProxyFactory<I> proxyFactory, I proxyInfo,
			AbstractDebuggerObjectModel model, P parent, String key, String typeHint) {
		this(proxyFactory, proxyInfo, model, parent, key, typeHint,
			parent.getSchema().getChildSchema(key));
	}

	/**
	 * Check if this object is being observed
	 * 
	 * <p>
	 * TODO: It'd be nice if we could know what is being observed: attributes, elements, console
	 * output, etc. In other words, the sub-types and overrides of the listeners.
	 * 
	 * <p>
	 * Note, if an implementation chooses to cull requests because no one is listening, it should
	 * take care to re-synchronize when a listener is added. The implementor will need to override
	 * {@link #addListener(TargetObjectListener)}.
	 * 
	 * @implNote The recommended pattern on the client side for keeping a synchronized cache is to
	 *           add a listener, and then retrieve the current elements. Thus, it is acceptable to
	 *           neglect invoking the callback on the new listener during re-synchronization.
	 *           However, more testing is needed to verify this doesn't cause problems when network
	 *           messaging is involved.
	 * 
	 * @return true if there is at least one listener on this object
	 * @deprecated Since the addition of model listeners, everything is always observed
	 */
	@Deprecated(forRemoval = true)
	protected boolean isObserved() {
		return !listeners.isEmpty();
	}

	@Override
	public CompletableFuture<Void> resync(boolean refreshAttributes, boolean refreshElements) {
		return CompletableFuture.allOf(fetchAttributes(refreshAttributes),
			fetchElements(refreshElements));
	}

	/**
	 * The elements for this object need to be updated, optionally invalidating caches
	 * 
	 * <p>
	 * Note that cache invalidation need not imply flushing {@link #elements}. In fact, it's
	 * preferable not to, as it becomes unclear how to invoke callbacks without some thrashing
	 * (i.e., one callback to remove everything, and another to re-populate). Instead, the entries
	 * in {@link #elements} should be assumed stale. The implementation should additionally not rely
	 * on any of its internal caches, in order to ensure the fetched elements are fresh. Once
	 * refreshed, only the changes from the stale cache to the fresh entries need be included in the
	 * callback.
	 * 
	 * <p>
	 * Note that this method completes with {@link Void}. The default implementation of
	 * {@link #fetchElements(boolean)} will complete with the cached elements, so this method should
	 * call {@link #changeElements(Collection, Collection, String)} before completion.
	 * 
	 * @param refresh true to invalidate all caches involved in handling this request
	 * @return a future which completes when the cache has been updated
	 */
	protected CompletableFuture<Void> requestElements(boolean refresh) {
		return AsyncUtils.NIL;
	}

	private boolean shouldRequestElements(boolean refresh) {
		if (refresh) {
			return true;
		}
		ResyncMode resync = getSchema().getElementResyncMode();
		return resync.shouldResync(curElemsRequest);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @implNote In general, an object should attempt to keep an up-to-date map of its elements,
	 *           usually by capturing the elements and subscribing to changes. This is not possible
	 *           in all circumstances. In those cases, implementations should override this method.
	 *           It may take whatever asynchronous action are necessary to get an up-to-date
	 *           response, then complete with {@link #elementsView}.
	 */
	@Override
	public CompletableFuture<? extends Map<String, ? extends E>> fetchElements(boolean refresh) {
		CompletableFuture<Void> req;
		synchronized (elements) {
			if (shouldRequestElements(refresh)) {
				curElemsRequest = model.gateFuture(requestElements(refresh));
			}
			req = curElemsRequest == null ? AsyncUtils.NIL : curElemsRequest;
		}
		return req.thenApply(__ -> getCachedElements());
	}

	@Override
	public CompletableFuture<? extends Map<String, ? extends E>> fetchElements() {
		return fetchElements(false);
	}

	@Override
	public Map<String, E> getCachedElements() {
		synchronized (model.lock) {
			return Map.copyOf(elements);
		}
	}

	@Override
	public Map<String, E> getCallbackElements() {
		return roCbElements;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @implNote Overridden here for type
	 */
	@Override
	public CompletableFuture<E> fetchElement(String index) {
		return fetchElements().thenApply(elems -> elems.get(index));
	}

	protected Map<String, E> combineElements(Collection<? extends E> autoKeyed,
			Map<String, ? extends E> mapKeyed) {
		Map<String, E> asMap = new LinkedHashMap<>();
		for (E e : autoKeyed) {
			asMap.put(e.getIndex(), e);
		}
		asMap.putAll(mapKeyed);
		return asMap;
	}

	/**
	 * Set the elements to the given collection, invoking listeners for the delta
	 * 
	 * <p>
	 * An existing element is left in place if it's identical to its replacement as in {@code ==}.
	 * This method also invalidates the sub-trees of removed elements, if any.
	 * 
	 * @param autoKeyed the desired set of elements where keys are given by the elements
	 * @param mapKeyed the desired map of elements with specified keys (usually for links)
	 * @param reason the reason for the change (used as the reason for invalidation)
	 * @return the delta from the previous elements
	 */
	public Delta<E, E> setElements(Collection<? extends E> autoKeyed,
			Map<String, ? extends E> mapKeyed, String reason) {
		if (!valid) {
			return Delta.empty();
		}
		Map<String, E> elements = combineElements(autoKeyed, mapKeyed);
		return setElements(elements, reason);
	}

	/**
	 * TODO: Consider multiple paths for objects, using schema to denote canonical location.
	 */
	public Delta<E, E> setElements(Collection<? extends E> elements, String reason) {
		return setElements(elements, Map.of(), reason);
	}

	private void updateCallbackElements(Delta<E, E> delta) {
		CompletableFuture.runAsync(() -> {
			synchronized (model.cbLock) {
				delta.apply(this.cbElements, Delta.SAME);
			}
		}, model.clientExecutor).exceptionally(ex -> {
			Msg.error(this, "Error updating elements before callback");
			return null;
		});
	}

	private Delta<E, E> setElements(Map<String, E> elements, String reason) {
		Delta<E, E> delta;
		synchronized (model.lock) {
			if (!valid) {
				return Delta.empty();
			}
			delta = Delta.computeAndSet(this.elements, elements, Delta.SAME);
			getSchema().validateElementDelta(getPath(), delta, enforcesStrictSchema());
			doInvalidateElements(delta.removed, reason);
			if (!delta.isEmpty()) {
				updateCallbackElements(delta);
				listeners.fire.elementsChanged(getProxy(), delta.getKeysRemoved(), delta.added);
			}
		}
		return delta;
	}

	/**
	 * Change the elements using the given "delta," invoking listeners
	 * 
	 * <p>
	 * An existing element is left in place if it's identical to its replacement as in {@code ==}.
	 * This method also invalidates the sub-trees of removed elements, if any.
	 * 
	 * @param remove the set of indices to remove
	 * @param autoKeyed the set of elements to add with the elements' keys
	 * @param mapKeyed the map of elements to add with given keys (usually for links)
	 * @param reason the reason for the change (used as the reason for invalidation)
	 * @return the actual delta from the previous to the current elements
	 */
	public Delta<E, E> changeElements(Collection<String> remove, Collection<? extends E> autoKeyed,
			Map<String, ? extends E> mapKeyed, String reason) {
		if (!valid) {
			return Delta.empty();
		}
		Map<String, E> add = combineElements(autoKeyed, mapKeyed);
		return changeElements(remove, add, reason);
	}

	/**
	 * TODO: Document me
	 */
	public Delta<E, E> changeElements(Collection<String> remove, Collection<? extends E> add,
			String reason) {
		return changeElements(remove, add, Map.of(), reason);
	}

	public Delta<E, E> changeElements(Collection<String> remove, Map<String, E> add,
			String reason) {
		Delta<E, E> delta;
		synchronized (model.lock) {
			if (!valid) {
				return Delta.empty();
			}
			delta = Delta.apply(this.elements, remove, add, Delta.SAME);
			getSchema().validateElementDelta(getPath(), delta, enforcesStrictSchema());
			doInvalidateElements(delta.removed, reason);
			if (!delta.isEmpty()) {
				updateCallbackElements(delta);
				listeners.fire.elementsChanged(getProxy(), delta.getKeysRemoved(), delta.added);
			}
		}
		return delta;
	}

	/**
	 * The attributes for this object need to be updated, optionally invalidating caches
	 * 
	 * <p>
	 * This method being called with -refresh- set is almost always an indication of something gone
	 * wrong. The client or user should not be attempting to refresh attributes except when there's
	 * reason to believe the model is not keeping its attribute cache up to date.
	 * 
	 * <p>
	 * This method otherwise operates analogously to {@link #requestElements(boolean)}.
	 * 
	 * @param refresh true to invalidate all caches involved in handling this request
	 * @return a future which completes when the cache has been updated
	 */
	protected CompletableFuture<Void> requestAttributes(boolean refresh) {
		return AsyncUtils.NIL;
	}

	private boolean shouldRequestAttributes(boolean refresh) {
		if (refresh) {
			return true;
		}
		ResyncMode resync = getSchema().getAttributeResyncMode();
		return resync.shouldResync(curAttrsRequest);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @implNote An object, except in very limited circumstances, must keep an up-to-date map of its
	 *           attributes, usually by capturing them at construction and subscribing to changes.
	 *           In those limited circumstances, it's usually the case that the object's parent has
	 *           update mode {@link TargetUpdateMode#SOLICITED}, which typically implies this
	 *           object's attributes are unchanging.
	 */
	@Override
	public CompletableFuture<? extends Map<String, ?>> fetchAttributes(boolean refresh) {
		CompletableFuture<Void> req;
		synchronized (attributes) {
			// update_mode does not affect attributes. They always behave as if UNSOLICITED.
			if (shouldRequestAttributes(refresh)) {
				curAttrsRequest = model.gateFuture(requestAttributes(refresh));
			}
			req = curAttrsRequest == null ? AsyncUtils.NIL : curAttrsRequest;
		}
		return req.thenApply(__ -> {
			synchronized (model.lock) {
				if (schema != null) { // TODO: Remove this. Schema should never be null.
					schema.validateRequiredAttributes(this, enforcesStrictSchema());
				}
				return getCachedAttributes();
			}
		});
	}

	@Override
	public CompletableFuture<? extends Map<String, ?>> fetchAttributes() {
		return fetchAttributes(false);
	}

	@Override
	public Map<String, ?> getCachedAttributes() {
		synchronized (model.lock) {
			return Map.copyOf(attributes);
		}
	}

	@Override
	public Map<String, ?> getCallbackAttributes() {
		return roCbAttributes;
	}

	@Override
	public Object getCachedAttribute(String name) {
		synchronized (model.lock) {
			return attributes.get(name);
		}
	}

	protected Map<String, Object> combineAttributes(Collection<? extends TargetObject> autoKeyed,
			Map<String, ?> mapKeyed) {
		Map<String, Object> asMap = new LinkedHashMap<>();
		for (TargetObject ca : autoKeyed) {
			asMap.put(ca.getName(), ca);
		}
		asMap.putAll(mapKeyed);
		return asMap;
	}

	/**
	 * Set the attributes to the given map, invoking listeners for the delta
	 * 
	 * <p>
	 * An existing attribute value is left in place if it's considered equal to its replacement as
	 * defined by {@link Objects#equals(Object, Object)}. This method also invalidates the sub-trees
	 * of removed non-reference object-valued attributes.
	 * 
	 * @param autoKeyed the desired set of object-valued attributes using the objects' keys
	 * @param mapKeyed the desired map of other attributes (usually links and primitive values)
	 * @param reason the reason for the change (used as the reason for invalidation)
	 * @return the delta from the previous attributes
	 */
	public Delta<?, ?> setAttributes(Collection<? extends TargetObject> autoKeyed,
			Map<String, ?> mapKeyed, String reason) {
		if (!valid) {
			return Delta.empty();
		}
		Map<String, ?> attributes = combineAttributes(autoKeyed, mapKeyed);
		return setAttributes(attributes, reason);
	}

	private void updateCallbackAttributes(Delta<Object, ?> delta) {
		CompletableFuture.runAsync(() -> {
			synchronized (model.cbLock) {
				delta.apply(this.cbAttributes, Delta.EQUAL);
			}
		}, model.clientExecutor).exceptionally(ex -> {
			Msg.error(this, "Error updating elements before callback");
			return null;
		});
	}

	/**
	 * TODO: Document me.
	 */
	public Delta<?, ?> setAttributes(Map<String, ?> attributes, String reason) {
		Delta<Object, ?> delta;
		synchronized (model.lock) {
			if (!valid) {
				return Delta.empty();
			}
			delta = Delta.computeAndSet(this.attributes, attributes, Delta.EQUAL);
			getSchema().validateAttributeDelta(getPath(), delta, enforcesStrictSchema());
			doInvalidateAttributes(delta.removed, reason);
			if (!delta.isEmpty()) {
				updateCallbackAttributes(delta);
				listeners.fire.attributesChanged(getProxy(), delta.getKeysRemoved(), delta.added);
			}
		}
		return delta;
	}

	/**
	 * Change the attributes using the given "delta," invoking listeners
	 * 
	 * <p>
	 * An existing attribute value is left in place if it's considered equal to its replacement as
	 * defined by {@link Objects#equals(Object, Object)}. This method also invalidates the sub-trees
	 * of removed non-reference object-valued attributes.
	 * 
	 * @param remove the set of names to remove
	 * @param autoKeyed the set of object-valued attributes to add using the objects' keys
	 * @param mapKeyed the map of other attributes to add (usually links and primitives)
	 * @param reason the reason for the change (used as the reason for invalidation)
	 * @return the actual delta from the previous to the current attributes
	 */
	public Delta<?, ?> changeAttributes(List<String> remove,
			Collection<? extends TargetObject> autoKeyed, Map<String, ?> mapKeyed, String reason) {
		if (!valid) {
			return Delta.empty();
		}
		Map<String, ?> add = combineAttributes(autoKeyed, mapKeyed);
		return changeAttributes(remove, add, reason);
	}

	public <T> Map<String, T> filterValid(String name, Map<String, T> map) {
		return map.entrySet().stream().filter(ent -> {
			T val = ent.getValue();
			if (!(val instanceof TargetObject)) {
				return true;
			}
			TargetObject obj = (TargetObject) val;
			if (obj.isValid()) {
				return true;
			}
			Msg.error(this, name + " " + ent.getKey() + " of " + getJoinedPath(".") +
				" linked to invalid object: " + obj.getJoinedPath("."));
			return false;
		}).collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue()));
	}

	/**
	 * This method may soon be made private. Consider
	 * {@link DefaultTargetObject#changeAttributes(List, Collection, Map, String)} instead.
	 * 
	 * <p>
	 * TODO: Consider allowing objects to move and/or occupy multiple paths. The schema could be
	 * used to specify the "canonical" location.
	 */
	public Delta<?, ?> changeAttributes(List<String> remove, Map<String, ?> add, String reason) {
		// add = filterValid("Attribute", add);
		Delta<Object, ?> delta;
		synchronized (model.lock) {
			if (!valid) {
				return Delta.empty();
			}
			delta = Delta.apply(this.attributes, remove, add, Delta.EQUAL);
			getSchema().validateAttributeDelta(getPath(), delta, enforcesStrictSchema());
			doInvalidateAttributes(delta.removed, reason);
			if (!delta.isEmpty()/* && !reason.equals("Default")*/) {
				updateCallbackAttributes(delta);
				listeners.fire.attributesChanged(getProxy(), delta.getKeysRemoved(), delta.added);
			}
		}
		return delta;
	}
}
