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

import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.EnumerableTargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.PathUtils;
import ghidra.lifecycle.Internal;
import ghidra.util.Msg;
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
public abstract class AbstractTargetObject<P extends TargetObject> implements SpiTargetObject {
	public static interface ProxyFactory<I> {
		SpiTargetObject createProxy(AbstractTargetObject<?> delegate, I info);
	}

	protected static final ProxyFactory<Void> THIS_FACTORY = (d, i) -> d;

	protected static final CompletableFuture<Map<String, TargetObject>> COMPLETED_EMPTY_ELEMENTS =
		CompletableFuture.completedFuture(Map.of());
	protected static final CompletableFuture<Map<String, Object>> COMPLETED_EMPTY_ATTRIBUTES =
		CompletableFuture.completedFuture(Map.of());

	protected final AbstractDebuggerObjectModel model;
	protected final SpiTargetObject proxy;
	protected final P parent;
	protected final List<String> path;
	protected final int hash;
	protected final String typeHint;
	protected final TargetObjectSchema schema;

	protected boolean valid = true;

	// TODO: Remove these, and just do invocations on model's listeners?
	protected final ListenerSet<DebuggerModelListener> listeners;

	public <I> AbstractTargetObject(ProxyFactory<I> proxyFactory, I proxyInfo,
			AbstractDebuggerObjectModel model, P parent, String key, String typeHint,
			TargetObjectSchema schema) {
		this.listeners = new ListenerSet<>(DebuggerModelListener.class, model.clientExecutor);
		this.model = model;
		listeners.addChained(model.listeners);
		this.parent = parent;
		if (parent == null) {
			this.path = key == null ? List.of() : List.of(key);
		}
		else {
			this.path = PathUtils.extend(parent.getPath(), key);
		}

		synchronized (model.lock) {
			model.removeExisting(path);

			this.hash = computeHashCode();
			this.typeHint = typeHint;

			this.schema = schema;
			this.proxy = proxyFactory.createProxy(this, proxyInfo);

			fireCreated();
		}
	}

	public AbstractTargetObject(AbstractDebuggerObjectModel model, P parent, String key,
			String typeHint, TargetObjectSchema schema) {
		this(THIS_FACTORY, null, model, parent, key, typeHint, schema);
	}

	protected void fireCreated() {
		SpiTargetObject proxy = getProxy();
		assert proxy != null;
		synchronized (model.lock) {
			model.objectCreated(proxy);
			listeners.fire.created(proxy);
		}
	}

	/**
	 * Get an alternative for {@code this} when invoking the listeners.
	 * 
	 * <p>
	 * Some implementations may use on a proxy-delegate pattern to implement target objects with
	 * various combinations of supported interfaces. When this pattern is employed, the delegate
	 * will extend {@link DefaultTargetObject}, causing {@code this} to refer to the delegate rather
	 * than the proxy. When invoking listeners, the proxy given by this method is used instead. The
	 * proxy is also used for schema interface validation.
	 * 
	 * @return the proxy or this
	 */
	public SpiTargetObject getProxy() {
		return proxy;
	}

	@Override
	public P getParent() {
		return parent;
	}

	@Override
	public <T extends TargetObject> T as(Class<T> iface) {
		return DebuggerObjectModel.requireIface(iface, getProxy(), path);
	}

	@Override
	public Collection<String> getInterfaceNames() {
		return Protected.getInterfaceNamesOf(getProxy().getClass());
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
	@Override
	public boolean enforcesStrictSchema() {
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
		//if (schema == null) {
		//	return String.format("<%s: path=%s model=%s schema=<null>>", getClass().getSimpleName(),
		//		getJoinedPath("."), getModel());
		//}
		return String.format("<%s: path=%s model=%s schema=%s>", getClass().getSimpleName(),
			getJoinedPath("."), getModel(), schema.getName());
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
	public void addListener(DebuggerModelListener l) {
		if (!valid) {
			throw new IllegalStateException("Object is no longer valid: " + getProxy());
		}
		listeners.add(l);
	}

	@Override
	public void removeListener(DebuggerModelListener l) {
		listeners.remove(l);
	}

	@Override
	public AbstractDebuggerObjectModel getModel() {
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

	protected void doInvalidate(TargetObject branch, String reason) {
		if (!valid) {
			return;
		}
		valid = false;
		model.objectInvalidated(getProxy());
		listeners.fire.invalidated(getProxy(), branch, reason);
		CompletableFuture.runAsync(() -> {
			listeners.clear();
			listeners.clearChained();
		}, model.clientExecutor).exceptionally(ex -> {
			Msg.error(this, "Error emptying invalidated object's listener set: ", ex);
			return null;
		});
	}

	protected void doInvalidateElements(Map<String, ?> elems, String reason) {
		for (Map.Entry<String, ?> ent : elems.entrySet()) {
			String name = ent.getKey();
			Object e = ent.getValue();
			if (e instanceof InvalidatableTargetObjectIf && e instanceof TargetObject) {
				InvalidatableTargetObjectIf obj = (InvalidatableTargetObjectIf) e;
				if (!PathUtils.isElementLink(getPath(), name, obj.getPath())) {
					obj.doInvalidateSubtree((TargetObject) e, reason);
				}
			}
		}
	}

	protected void doInvalidateElements(TargetObject branch, Map<String, ?> elems, String reason) {
		for (Map.Entry<String, ?> ent : elems.entrySet()) {
			String name = ent.getKey();
			Object e = ent.getValue();
			if (e instanceof InvalidatableTargetObjectIf) {
				InvalidatableTargetObjectIf obj = (InvalidatableTargetObjectIf) e;
				if (!PathUtils.isElementLink(getPath(), name, obj.getPath())) {
					obj.doInvalidateSubtree(branch, reason);
				}
			}
		}
	}

	protected void doInvalidateAttributes(Map<String, ?> attrs, String reason) {
		for (Map.Entry<String, ?> ent : attrs.entrySet()) {
			String name = ent.getKey();
			Object a = ent.getValue();
			if (a instanceof InvalidatableTargetObjectIf && a instanceof TargetObject) {
				InvalidatableTargetObjectIf obj = (InvalidatableTargetObjectIf) a;
				if (!PathUtils.isLink(getPath(), name, obj.getPath())) {
					obj.doInvalidateSubtree((TargetObject) a, reason);
				}
			}
		}
	}

	protected void doInvalidateAttributes(TargetObject branch, Map<String, ?> attrs,
			String reason) {
		for (Map.Entry<String, ?> ent : attrs.entrySet()) {
			String name = ent.getKey();
			Object a = ent.getValue();
			if (a instanceof InvalidatableTargetObjectIf) {
				InvalidatableTargetObjectIf obj = (InvalidatableTargetObjectIf) a;
				if (!PathUtils.isLink(getPath(), name, obj.getPath())) {
					obj.doInvalidateSubtree(branch, reason);
				}
			}
		}
	}

	@Override
	public void doInvalidateSubtree(TargetObject branch, String reason) {
		// Pre-ordered traversal
		doInvalidate(branch, reason);
		doInvalidateElements(branch, getCachedElements(), reason);
		doInvalidateAttributes(branch, getCachedAttributes(), reason);
	}

	@Override
	public void invalidateSubtree(TargetObject branch, String reason) {
		synchronized (model.lock) {
			doInvalidateSubtree(branch, reason);
		}
	}

	/**
	 * Get the listener set
	 * 
	 * <p>
	 * TODO: This method should only be used by the internal implementation. It's not exposed on the
	 * {@link TargetObject} interface, but it could be dangerous to have it here, since clients
	 * could cast to {@link AbstractTargetObject} and get at it, even if the implementation's jar is
	 * excluded from the compile-time classpath.
	 * 
	 * @return the listener set
	 */
	@Internal
	public ListenerSet<DebuggerModelListener> getListeners() {
		return listeners;
	}
}
