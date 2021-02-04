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

import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.CollectionUtils.Delta;
import ghidra.dbg.util.PathUtils;
import ghidra.dbg.util.PathUtils.TargetObjectKeyComparator;
import ghidra.util.Msg;
import ghidra.util.datastruct.ListenerSet;

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
	protected final Map<String, E> elements = new TreeMap<>(TargetObjectKeyComparator.ELEMENT);
	protected CompletableFuture<Void> curElemsRequest;

	/** Note modifying this directly subverts notifications */
	protected final Map<String, Object> attributes =
		new TreeMap<>(TargetObjectKeyComparator.ATTRIBUTE);
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
	public DefaultTargetObject(DebuggerObjectModel model, P parent, String key, String typeHint) {
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
	public DefaultTargetObject(DebuggerObjectModel model, P parent, String key, String typeHint,
			TargetObjectSchema schema) {
		super(model, parent, key, typeHint, schema);
		changeAttributes(List.of(), List.of(), Map.of(DISPLAY_ATTRIBUTE_NAME,
			key == null ? "<root>" : key, UPDATE_MODE_ATTRIBUTE_NAME, TargetUpdateMode.UNSOLICITED),
			"Initialized");
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
	 */
	protected boolean isObserved() {
		return !listeners.isEmpty();
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
			if (refresh || curElemsRequest == null || curElemsRequest.isCompletedExceptionally() ||
				getUpdateMode() == TargetUpdateMode.SOLICITED) {
				curElemsRequest = requestElements(refresh);
			}
			req = curElemsRequest;
		}
		return req.thenApply(__ -> getCachedElements());
	}

	@Override
	public CompletableFuture<? extends Map<String, ? extends E>> fetchElements() {
		return fetchElements(false);
	}

	@Override
	public Map<String, E> getCachedElements() {
		synchronized (elements) {
			return Map.copyOf(elements);
		}
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

	protected Map<String, E> combineElements(Collection<? extends E> canonical,
			Map<String, ? extends E> links) {
		Map<String, E> asMap = new LinkedHashMap<>();
		for (E e : canonical) {
			if (!PathUtils.parent(e.getPath()).equals(getPath())) {
				Msg.error(this, "Link found in canonical elements of " + parent + ": " + e);
			}
			asMap.put(e.getIndex(), e);
		}
		for (Map.Entry<String, ? extends E> ent : links.entrySet()) {
			if (!PathUtils.isLink(getPath(), PathUtils.makeKey(ent.getKey()),
				ent.getValue().getPath())) {
				//Msg.error(this, "Canonical element found in links: " + ent);
			}
			asMap.put(ent.getKey(), ent.getValue());
		}
		return asMap;
	}

	/**
	 * Set the elements to the given collection, invoking listeners for the delta
	 * 
	 * <p>
	 * An existing element is left in place if it's identical to its replacement as in {@code ==}.
	 * This method also invalidates the sub-trees of removed elements, if any.
	 * 
	 * @param canonical the desired set of canonical elements
	 * @param links the desired map of linked elements
	 * @param reason the reason for the change (used as the reason for invalidation)
	 * @return the delta from the previous elements
	 */
	public Delta<E, E> setElements(Collection<? extends E> canonical,
			Map<String, ? extends E> links, String reason) {
		Map<String, E> elements = combineElements(canonical, links);
		return setElements(elements, reason);
	}

	/**
	 * TODO: Consider multiple paths for objects, using schema to denote canonical location.
	 */
	public Delta<E, E> setElements(Collection<? extends E> elements, String reason) {
		return setElements(elements, Map.of(), reason);
	}

	private Delta<E, E> setElements(Map<String, E> elements, String reason) {
		Delta<E, E> delta;
		synchronized (this.elements) {
			delta = Delta.computeAndSet(this.elements, elements, Delta.SAME);
		}
		TargetObjectSchema schemax = getSchema();
		if (schemax != null) {
			schemax.validateElementDelta(getPath(), delta, enforcesStrictSchema());
		}
		doInvalidateElements(delta.removed.values(), reason);
		if (!delta.isEmpty()) {
			listeners.fire.elementsChanged(getProxy(), delta.getKeysRemoved(), delta.added);
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
	 * @param addCanonical the set of canonical elements to add
	 * @param addLinks the map of linked elements to add
	 * @param reason the reason for the change (used as the reason for invalidation)
	 * @return the actual delta from the previous to the current elements
	 */
	public Delta<E, E> changeElements(Collection<String> remove,
			Collection<? extends E> addCanonical, Map<String, ? extends E> addLinks,
			String reason) {
		Map<String, E> add = combineElements(addCanonical, addLinks);
		return changeElements(remove, add, reason);
	}

	/**
	 * TODO: Document me
	 */
	public Delta<E, E> changeElements(Collection<String> remove, Collection<? extends E> add,
			String reason) {
		return changeElements(remove, add, Map.of(), reason);
	}

	private Delta<E, E> changeElements(Collection<String> remove, Map<String, E> add,
			String reason) {
		Delta<E, E> delta;
		synchronized (elements) {
			delta = Delta.apply(this.elements, remove, add, Delta.SAME);
		}
		TargetObjectSchema schemax = getSchema();
		if (schemax != null) {
			schemax.validateElementDelta(getPath(), delta, enforcesStrictSchema());
		}
		doInvalidateElements(delta.removed.values(), reason);
		if (!delta.isEmpty()) {
			listeners.fire.elementsChanged(getProxy(), delta.getKeysRemoved(), delta.added);
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
			if (refresh || curAttrsRequest == null || curAttrsRequest.isCompletedExceptionally()) {
				curAttrsRequest = requestAttributes(refresh);
			}
			req = curAttrsRequest;
		}
		return req.thenApply(__ -> getCachedAttributes());
	}

	@Override
	public CompletableFuture<? extends Map<String, ?>> fetchAttributes() {
		return fetchAttributes(false);
	}

	@Override
	public Map<String, ?> getCachedAttributes() {
		synchronized (attributes) {
			return Map.copyOf(attributes);
		}
	}

	@Override
	public Object getCachedAttribute(String name) {
		synchronized (attributes) {
			return attributes.get(name);
		}
	}

	protected Map<String, Object> combineAttributes(
			Collection<? extends TargetObjectRef> canonicalObjects, Map<String, ?> linksAndValues) {
		Map<String, Object> asMap = new LinkedHashMap<>();
		for (TargetObjectRef ca : canonicalObjects) {
			if (!PathUtils.parent(ca.getPath()).equals(getPath())) {
				Msg.error(this, "Link found in canonical attributes: " + ca);
			}
			asMap.put(ca.getName(), ca);
		}
		for (Map.Entry<String, ?> ent : linksAndValues.entrySet()) {
			Object av = ent.getValue();
			if (av instanceof TargetObjectRef) {
				TargetObjectRef link = (TargetObjectRef) av;
				if (!PathUtils.isLink(getPath(), ent.getKey(), link.getPath())) {
					//Msg.error(this, "Canonical attribute found in links: " + ent);
				}
			}
			asMap.put(ent.getKey(), ent.getValue());
		}
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
	 * @param canonicalObjects the desired set of canonical object-valued attributes
	 * @param linksAndValues the desired map of other attributes
	 * @param reason the reason for the change (used as the reason for invalidation)
	 * @return the delta from the previous attributes
	 */
	public Delta<?, ?> setAttributes(Collection<? extends TargetObject> canonicalObjects,
			Map<String, ?> linksAndValues, String reason) {
		Map<String, ?> attributes = combineAttributes(canonicalObjects, linksAndValues);
		return setAttributes(attributes, reason);
	}

	/**
	 * TODO: Document me.
	 */
	public Delta<?, ?> setAttributes(Map<String, ?> attributes, String reason) {
		Delta<?, ?> delta;
		synchronized (this.attributes) {
			delta = Delta.computeAndSet(this.attributes, attributes, Delta.EQUAL);
		}
		TargetObjectSchema schemax = getSchema();
		if (schemax != null) {
			schemax.validateAttributeDelta(getPath(), delta, enforcesStrictSchema());
		}
		doInvalidateAttributes(delta.removed, reason);
		if (!delta.isEmpty()) {
			listeners.fire.attributesChanged(getProxy(), delta.getKeysRemoved(), delta.added);
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
	 * @param addCanonicalObjects the set of canonical object-valued attributes to add
	 * @param addLinksAndValues the map of other attributes to add
	 * @param reason the reason for the change (used as the reason for invalidation)
	 * @return the actual delta from the previous to the current attributes
	 */
	public Delta<?, ?> changeAttributes(List<String> remove,
			Collection<? extends TargetObject> addCanonicalObjects,
			Map<String, ?> addLinksAndValues, String reason) {
		Map<String, ?> add = combineAttributes(addCanonicalObjects, addLinksAndValues);
		return changeAttributes(remove, add, reason);
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
		Delta<?, ?> delta;
		synchronized (attributes) {
			delta = Delta.apply(this.attributes, remove, add, Delta.EQUAL);
		}
		TargetObjectSchema schemax = getSchema();
		if (schemax != null) {
			schemax.validateAttributeDelta(getPath(), delta, enforcesStrictSchema());
		}
		doInvalidateAttributes(delta.removed, reason);
		if (!delta.isEmpty()) {
			listeners.fire.attributesChanged(getProxy(), delta.getKeysRemoved(), delta.added);
		}
		return delta;
	}

	public ListenerSet<TargetObjectListener> getListeners() {
		return listeners;
	}
}
