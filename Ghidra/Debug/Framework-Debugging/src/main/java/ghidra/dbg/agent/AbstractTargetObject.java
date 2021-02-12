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

import java.lang.reflect.Proxy;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.EnumerableTargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.PathUtils;
import ghidra.util.datastruct.ListenerSet;

/**
 * An abstract implementation of {@link TargetObject}
 * 
 * <p>
 * Implementors should probably use {@link DefaultTargetObject} as the base class for all objects in
 * the model. If your model employs proxies (i.e., using
 * {@link Proxy#newProxyInstance(ClassLoader, Class[], java.lang.reflect.InvocationHandler)}),
 * please see {@link InvalidatableTargetObjectIf} to ensure subtree invalidation is handled
 * properly.
 * 
 * @param <P> the type of the parent
 */
public abstract class AbstractTargetObject<P extends TargetObject>
		implements TargetObject, InvalidatableTargetObjectIf {
	protected static final CompletableFuture<Map<String, TargetObject>> COMPLETED_EMPTY_ELEMENTS =
		CompletableFuture.completedFuture(Map.of());
	protected static final CompletableFuture<Map<String, Object>> COMPLETED_EMPTY_ATTRIBUTES =
		CompletableFuture.completedFuture(Map.of());

	protected final DebuggerObjectModel model;
	protected final P parent;
	protected final CompletableFuture<P> completedParent;
	protected final List<String> path;
	protected final int hash;
	protected final String typeHint;
	protected final TargetObjectSchema schema;

	protected boolean valid = true;

	protected final ListenerSet<TargetObjectListener> listeners;

	public AbstractTargetObject(DebuggerObjectModel model, P parent, String key, String typeHint,
			TargetObjectSchema schema) {
		this.listeners = new ListenerSet<>(TargetObjectListener.class, model.getClientExecutor());
		this.model = model;
		this.parent = parent;
		this.completedParent = CompletableFuture.completedFuture(parent);
		if (parent == null) {
			this.path = key == null ? List.of() : List.of(key);
		}
		else {
			this.path = PathUtils.extend(parent.getPath(), key);
		}
		this.hash = computeHashCode();
		this.typeHint = typeHint;

		this.schema = schema;
	}

	/**
	 * Get an alternative for {@code this} when invoking the listeners.
	 * 
	 * <p>
	 * Some implementations may use on a proxy-delegate pattern to implement target objects with
	 * various combinations of supported interfaces. When this pattern is employed, the delegate
	 * will extend {@link DefaultTargetObject}, causing {@code this} to refer to the delegate rather
	 * than the proxy. When invoking listeners, the proxy given by this method is used instead. By
	 * default, it simply returns {@code this}, providing the expected behavior for typical
	 * implementations. The proxy is also used for schema interface validation.
	 * 
	 * @return the proxy or this
	 */
	public TargetObject getProxy() {
		return this;
	}

	/**
	 * Check if this object strictly conforms to the schema
	 * 
	 * <p>
	 * This method exists to support the transition to schemas. If this method returns false, schema
	 * violations are logged, but whatever changes were requested that caused the violation are
	 * still allowed to occur. If it returns true, then any schema violation will cause an
	 * {@link AssertionError}. Because schema violations are presumed to be programming errors,
	 * there is no guarantee of consistency after an exception is thrown. In general, models without
	 * explicit schemas should not fail validation, since objects will likely be assigned
	 * {@link EnumerableTargetObjectSchema#ANY}. When developing a schema for an existing model, it
	 * may be useful to override this to return true to fail fast.
	 * 
	 * @return true to throw exceptions on schema violations.
	 */
	protected boolean enforcesStrictSchema() {
		return false;
	}

	@Override
	public boolean equals(Object obj) {
		return doEquals(obj);
	}

	@Override
	public int hashCode() {
		return hash;
	}

	@Override
	public String toString() {
		if (schema == null) {
			return String.format("<%s: path=%s model=%s schema=NULL>", getClass().getSimpleName(),
				path, getModel());
		}
		return String.format("<%s: path=%s model=%s schema=%s>", getClass().getSimpleName(), path,
			getModel(), schema.getName());
	}

	@Override
	public String getTypeHint() {
		return typeHint;
	}

	@Override
	public TargetObjectSchema getSchema() {
		return schema;
	}

	@Override
	public boolean isValid() {
		return valid;
	}

	@Override
	public void addListener(TargetObjectListener l) {
		listeners.add(l);
	}

	@Override
	public void removeListener(TargetObjectListener l) {
		listeners.remove(l);
	}

	@Override
	public DebuggerObjectModel getModel() {
		return model;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Overridden to avoid an infinite loop / stack overflow
	 */
	@Override
	public CompletableFuture<? extends Map<String, ? extends TargetObject>> fetchElements() {
		return COMPLETED_EMPTY_ELEMENTS;
	}

	@Override
	public CompletableFuture<? extends TargetObject> fetchElement(String index) {
		return fetchElements().thenApply(elements -> elements.get(index));
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Overridden to avoid an infinite loop / stack overflow
	 */
	@Override
	public CompletableFuture<? extends Map<String, ?>> fetchAttributes() {
		return COMPLETED_EMPTY_ATTRIBUTES;
	}

	@Override
	public Object getProtocolID() {
		return getPath();
	}

	@Override
	public List<String> getPath() {
		return path;
	}

	@Override
	public CompletableFuture<? extends P> fetchParent() {
		return completedParent;
	}

	/**
	 * Get the parent immediately
	 * 
	 * Since the parent is fixed and known to the implementation, it can be retrieved immediately.
	 * 
	 * @return the parent
	 */
	public P getImplParent() {
		return parent;
	}

	protected void doInvalidate(String reason) {
		valid = false;
		listeners.fire.invalidated(this, reason);
	}

	protected void doInvalidateElements(Collection<?> elems, String reason) {
		for (Object e : elems) {
			if (e instanceof InvalidatableTargetObjectIf) {
				InvalidatableTargetObjectIf obj = (InvalidatableTargetObjectIf) e;
				obj.invalidateSubtree(reason);
			}
		}
	}

	protected void doInvalidateAttributes(Map<String, ?> attrs, String reason) {
		for (Map.Entry<String, ?> ent : attrs.entrySet()) {
			String name = ent.getKey();
			Object a = ent.getValue();
			if (a instanceof InvalidatableTargetObjectIf) {
				InvalidatableTargetObjectIf obj = (InvalidatableTargetObjectIf) a;
				if (!PathUtils.isLink(getPath(), name, obj.getPath())) {
					obj.invalidateSubtree(reason);
				}
			}
		}
	}

	@Override
	public void invalidateSubtree(String reason) {
		// Pre-ordered traversal
		doInvalidate(reason);
		doInvalidateElements(getCachedElements().values(), reason);
		doInvalidateAttributes(getCachedAttributes(), reason);
	}
}
