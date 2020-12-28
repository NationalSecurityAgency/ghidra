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
package ghidra.dbg.gadp.client;

import java.lang.annotation.Annotation;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.ref.Cleaner.Cleanable;
import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.gadp.GadpRegistry;
import ghidra.dbg.gadp.client.annot.GadpAttributeChangeCallback;
import ghidra.dbg.gadp.client.annot.GadpEventHandler;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.gadp.protocol.Gadp.EventNotification.EvtCase;
import ghidra.dbg.gadp.util.GadpValueUtils;
import ghidra.dbg.memory.CachedMemory;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetAccessConditioned.TargetAccessibility;
import ghidra.dbg.target.TargetAccessConditioned.TargetAccessibilityListener;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointAction;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.CollectionUtils.Delta;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.AddressSpace;
import ghidra.util.Msg;
import ghidra.util.datastruct.ListenerSet;
import utilities.util.ProxyUtilities;

/**
 * This class is meant to be used as a delegate to a composed proxy
 */
public class DelegateGadpClientTargetObject implements GadpClientTargetObject {
	protected abstract static class GadpHandlerMap<A extends Annotation, K> {
		protected final Class<A> annotationType;
		protected final Class<?>[] paramClasses;
		protected final Map<K, MethodHandle> handles = new HashMap<>();

		public GadpHandlerMap(Class<A> annotationType, Class<?>[] paramClasses) {
			this.annotationType = annotationType;
			this.paramClasses = paramClasses;
		}

		protected abstract K getKey(A annot);

		protected void compose(GadpHandlerMap<A, K> that) {
			for (Map.Entry<K, MethodHandle> ent : that.handles.entrySet()) {
				MethodHandle old = handles.put(ent.getKey(), ent.getValue());
				if (old != null) {
					throw new AssertionError("Conflict over handler for " + ent.getKey() +
						": " + old + " and " + ent.getValue());
				}
			}
		}

		protected void register(K key, MethodHandle handle) {
			MethodHandle old = handles.put(key, handle);
			if (old != null) {
				throw new AssertionError(
					"Conflict over handler for " + key + ": " + old + " and " + handle);
			}
		}

		protected void registerInterface(Class<? extends TargetObject> iface) {
			for (Method method : iface.getDeclaredMethods()) {
				A annot = method.getDeclaredAnnotation(annotationType);
				if (annot == null) {
					continue;
				}
				if (!Arrays.equals(paramClasses, method.getParameterTypes())) {
					throw new AssertionError("@" + annotationType.getSimpleName() +
						" methods must have typed parameters: " + paramClasses);
				}
				MethodHandle handle;
				try {
					handle = ProxyUtilities.getSuperMethodHandle(method, LOOKUP);
				}
				catch (IllegalAccessException e) {
					throw new AssertionError(e);
				}
				register(getKey(annot), handle);
			}
		}

		protected void handle(GadpClientTargetObject proxy, K key, Object... params) {
			MethodHandle handle = handles.get(key);
			if (handle == null) {
				//Msg.info(this, "Received unknown handler key: " + key);
				return;
			}
			try {
				handle.bindTo(proxy).invokeWithArguments(params);
			}
			catch (Throwable e) {
				Msg.error(this, "Problem processing key: " + key, e);
			}
		}
	}

	protected static class GadpEventHandlerMap extends GadpHandlerMap<GadpEventHandler, EvtCase> {
		protected static final Class<?>[] PARAMETER_CLASSES =
			new Class<?>[] { Gadp.EventNotification.class };

		public GadpEventHandlerMap(Set<Class<? extends TargetObject>> ifaces) {
			super(GadpEventHandler.class, PARAMETER_CLASSES);
			for (Class<? extends TargetObject> iface : ifaces) {
				registerInterface(iface);
			}
		}

		@Override
		protected EvtCase getKey(GadpEventHandler annot) {
			return annot.value();
		}
	}

	protected static class GadpAttributeChangeCallbackMap
			extends GadpHandlerMap<GadpAttributeChangeCallback, String> {
		protected static final Class<?>[] PARAMETER_CLASSES = new Class<?>[] { Object.class };

		public GadpAttributeChangeCallbackMap(Set<Class<? extends TargetObject>> ifaces) {
			super(GadpAttributeChangeCallback.class, PARAMETER_CLASSES);
			for (Class<? extends TargetObject> iface : ifaces) {
				registerInterface(iface);
			}
		}

		@Override
		protected String getKey(GadpAttributeChangeCallback annot) {
			return annot.value();
		}
	}

	protected static class ProxyState implements Runnable {
		protected final GadpClient client;
		protected final List<String> path;
		protected boolean valid = true;

		public ProxyState(GadpClient client, List<String> path) {
			this.client = client;
			this.path = path;
		}

		@Override
		public void run() {
			if (!valid) {
				return;
			}
			client.unsubscribe(path).exceptionally(e -> {
				Msg.error(this, "Could not unsubscribe from " + path + ": " + e);
				return null;
			});
		}
	}

	protected static final MethodHandles.Lookup LOOKUP = MethodHandles.lookup();
	protected static final Map<Set<Class<? extends TargetObject>>, GadpEventHandlerMap> EVENT_HANDLER_MAPS_BY_COMPOSITION =
		new HashMap<>();
	protected static final Map<Set<Class<? extends TargetObject>>, GadpAttributeChangeCallbackMap> ATTRIBUTE_CHANGE_CALLBACKS_MAPS_BY_COMPOSITION =
		new HashMap<>();

	protected static GadpClientTargetObject makeModelProxy(GadpClient client, List<String> path,
			String typeHint, List<String> ifaceNames) {
		List<Class<? extends TargetObject>> ifaces = TargetObject.getInterfacesByName(ifaceNames);
		List<Class<? extends TargetObject>> mixins = GadpRegistry.getMixins(ifaces);
		return new DelegateGadpClientTargetObject(client, path, typeHint, ifaceNames, ifaces,
			mixins).proxy;
	}

	protected final ProxyState state;
	protected final int hash;
	protected final Cleanable cleanable;

	private final GadpClientTargetObject proxy;
	private TargetObjectSchema schema; // lazily evaluated
	private final String typeHint;
	private final List<String> ifaceNames;
	private final List<Class<? extends TargetObject>> ifaces;
	private final GadpEventHandlerMap eventHandlers;
	private final GadpAttributeChangeCallbackMap attributeChangeCallbacks;
	protected final ListenerSet<TargetObjectListener> listeners =
		new ListenerSet<>(TargetObjectListener.class);

	// TODO: Use path element comparators?
	protected final Map<String, TargetObjectRef> elements = new TreeMap<>();
	// TODO: Use path element comparators?
	protected final Map<String, Object> attributes = new TreeMap<>();

	protected Map<AddressSpace, CachedMemory> memCache = null; // Becomes active if this is a TargetMemory
	protected Map<String, byte[]> regCache = null; // Becomes active if this is a TargtRegisterBank
	protected ListenerSet<TargetBreakpointAction> actions = null; // Becomes active is this is a TargetBreakpointSpec

	public DelegateGadpClientTargetObject(GadpClient client, List<String> path, String typeHint,
			List<String> ifaceNames, List<Class<? extends TargetObject>> ifaces,
			List<Class<? extends TargetObject>> mixins) {
		this.state = new ProxyState(client, path);
		this.hash = computeHashCode();
		this.cleanable = GadpClient.CLEANER.register(this, state);

		this.proxy = ProxyUtilities.composeOnDelegate(GadpClientTargetObject.class,
			this, mixins, MethodHandles.lookup());
		this.typeHint = typeHint;
		this.ifaceNames = ifaceNames;
		this.ifaces = ifaces;

		Set<Class<? extends TargetObject>> allMixins = new HashSet<>(mixins);
		allMixins.add(GadpClientTargetObject.class);
		this.eventHandlers = EVENT_HANDLER_MAPS_BY_COMPOSITION.computeIfAbsent(allMixins,
			GadpEventHandlerMap::new);
		this.attributeChangeCallbacks =
			ATTRIBUTE_CHANGE_CALLBACKS_MAPS_BY_COMPOSITION.computeIfAbsent(allMixins,
				GadpAttributeChangeCallbackMap::new);
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
		return "<GADP TargetObject: '" + PathUtils.toString(getPath()) + "' via " +
			getModel().description + ">";
	}

	@Override
	public GadpClient getModel() {
		return state.client;
	}

	@Override
	public List<String> getProtocolID() {
		return state.path;
	}

	@Override
	public List<String> getPath() {
		return state.path;
	}

	@Override
	public TargetObjectSchema getSchema() {
		if (schema == null) {
			schema = getModel().getRootSchema().getSuccessorSchema(getPath());
		}
		return schema;
	}

	@Override
	public String getTypeHint() {
		return typeHint;
	}

	@Override
	public Collection<String> getInterfaceNames() {
		return ifaceNames;
	}

	@Override
	public Collection<Class<? extends TargetObject>> getInterfaces() {
		return ifaces;
	}

	@Override
	public boolean isValid() {
		return state.valid;
	}

	@Override
	public Map<String, TargetObjectRef> getCachedElements() {
		synchronized (this.elements) {
			return Map.copyOf(elements);
		}
	}

	@Override
	public Map<String, ?> getCachedAttributes() {
		synchronized (this.attributes) {
			return Map.copyOf(attributes);
		}
	}

	@Override
	public Object getCachedAttribute(String name) {
		synchronized (attributes) {
			return attributes.get(name);
		}
	}

	protected void putCachedProxy(String key, GadpClientTargetObject proxy) {
		if (PathUtils.isIndex(key)) {
			synchronized (elements) {
				elements.put(PathUtils.parseIndex(key), proxy);
			}
		}
		else {
			synchronized (attributes) {
				attributes.put(key, proxy);
			}
		}
	}

	protected Optional<Object> cachedChild(String key) {
		/**
		 * TODO: Object metadata which indicates whether the attributes/elements support
		 * subscription (push notifications). Otherwise, if the parent is cached, GADP will assume
		 * the server is sending updates. If the model actually requires pulling, the GADP client
		 * will not know, and will instead use its (likely stale) cache.
		 */
		assert key != null;
		if (PathUtils.isIndex(key)) {
			/**
			 * NOTE: I do not need to check the subscription level. The level has to do with
			 * including object info. Having OBJECT level is sufficient to have up-to-date keys.
			 */
			synchronized (elements) {
				return Optional.ofNullable(elements.get(PathUtils.parseIndex(key)));
			}
		}
		assert PathUtils.isName(key);
		synchronized (attributes) {
			return Optional.ofNullable(attributes.get(key));
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * The delegate has to override defaults which introspect on, or otherwise would leak "this".
	 * "this" is the delegate; we must instead operate on the proxy.
	 */
	@Override
	public <T extends TypedTargetObject<T>> T as(Class<T> iface) {
		return DebuggerObjectModel.requireIface(iface, proxy, state.path);
	}

	@Override
	public CompletableFuture<? extends TargetObject> fetch() {
		return CompletableFuture.completedFuture(proxy);
	}

	@Override
	public CompletableFuture<?> fetchAttribute(String name) {
		if (!PathUtils.isInvocation(name)) {
			return GadpClientTargetObject.super.fetchAttribute(name);
		}
		return state.client.fetchModelValue(PathUtils.extend(state.path, name));
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
	public DelegateGadpClientTargetObject getDelegate() {
		return this;
	}

	public void updateWithInfo(Gadp.ModelObjectInfo info) {
		Map<String, TargetObjectRef> elements =
			GadpValueUtils.getElementMap(this, info.getElementIndexList());
		Map<String, Object> attributes =
			GadpValueUtils.getAttributeMap(this, info.getAttributeList());

		Delta<TargetObjectRef, TargetObjectRef> deltaE = setElements(elements);
		Delta<Object, Object> deltaA = setAttributes(attributes);
		fireElementsChanged(deltaE);
		fireAttributesChanged(deltaA);
	}

	public void updateWithDelta(Gadp.ModelObjectDelta delta) {
		Map<String, TargetObjectRef> elementsAdded =
			GadpValueUtils.getElementMap(this, delta.getIndexAddedList());
		Map<String, Object> attributesAdded =
			GadpValueUtils.getAttributeMap(this, delta.getAttributeAddedList());

		Delta<TargetObjectRef, TargetObjectRef> deltaE =
			updateElements(Delta.create(delta.getIndexRemovedList(), elementsAdded));
		Delta<Object, Object> deltaA =
			updateAttributes(Delta.create(delta.getAttributeRemovedList(), attributesAdded));
		fireElementsChanged(deltaE);
		fireAttributesChanged(deltaA);
	}

	protected void handleEvent(Gadp.EventNotification notify) {
		eventHandlers.handle(proxy, notify.getEvtCase(), notify);
	}

	/**
	 * Translate the given attribute change into an interface-specific property change, if
	 * applicable, and invokes the appropriate listeners
	 * 
	 * @implNote The model interface allow listening for attribute changes in general, as well as
	 *           some interface-specific property changes. The convention in model is for such
	 *           properties to be encoded as an attribute with a specified name, e.g., the
	 *           'accessible' attribute encodes the valcachedAue for
	 *           {@link TargetAccessConditioned#getAccessibility()}, and changes will invoke
	 *           {@link TargetAccessibilityListener#accessibilityChanged(TargetAccessConditioned, TargetAccessibility)}.
	 *           Taking advantage of the general attribute getting/change-listening convention, GADP
	 *           communicates only the attribute changes, and then invokes the corresponding
	 *           interface-specific property change listeners on the client side. So long as the
	 *           model implementation on the server side follows the convention, then the
	 *           client-side proxies will obey the same. If not, then client-side behavior is
	 *           undefined.
	 * 
	 * @see GadpAttributeChangeCallback
	 * 
	 * @param name the name of the attribute
	 * @param value the new value of the attribute
	 */
	protected void handleAttributeChange(String name, Object value) {
		attributeChangeCallbacks.handle(proxy, name, value);
	}

	protected <U extends TargetObjectRef> Delta<TargetObjectRef, U> updateElements(
			Delta<TargetObjectRef, U> delta) {
		synchronized (this.elements) {
			return delta.apply(elements);
		}
	}

	protected <U extends TargetObjectRef> Delta<TargetObjectRef, U> setElements(
			Map<String, U> elements) {
		synchronized (this.elements) {
			return Delta.computeAndSet(this.elements, elements, Delta.SAME);
		}
	}

	protected <U> Delta<Object, U> updateAttributes(Delta<Object, U> delta) {
		synchronized (this.attributes) {
			return delta.apply(attributes, Delta.EQUAL);
		}
	}

	protected <U> Delta<Object, U> setAttributes(Map<String, U> attributes) {
		synchronized (this.attributes) {
			return Delta.computeAndSet(this.attributes, attributes, Delta.EQUAL);
		}
	}

	protected void fireElementsChanged(Delta<?, ? extends TargetObjectRef> delta) {
		if (!delta.isEmpty()) {
			listeners.fire.elementsChanged(proxy, delta.getKeysRemoved(), delta.added);
		}
	}

	protected void fireAttributesChanged(Delta<?, ?> delta) {
		if (!delta.isEmpty()) {
			listeners.fire.attributesChanged(proxy, delta.getKeysRemoved(), delta.added);
			for (Map.Entry<String, ?> a : delta.added.entrySet()) {
				handleAttributeChange(a.getKey(), a.getValue());
			}
		}
	}

	protected void doInvalidateSubtree(String reason) {
		state.client.invalidateSubtree(state.path, reason);
	}

	protected void doInvalidate(String reason) {
		state.valid = false;
		listeners.fire.invalidated(proxy, reason);
	}

	protected void assertValid() {
		if (!state.valid) {
			throw new IllegalStateException("Object is no longer valid: " + toString());
		}
	}

	protected void doClearCaches() {
		clearMemCacheEntries();
		clearRegisterCacheEntries();
	}

	@Override
	public synchronized CompletableFuture<Void> invalidateCaches() {
		assertValid();
		doClearCaches();
		return state.client.sendChecked(Gadp.CacheInvalidateRequest.newBuilder()
				.setPath(GadpValueUtils.makePath(state.path)),
			Gadp.CacheInvalidateReply.getDefaultInstance()).thenApply(rep -> null);
	}

	protected synchronized CachedMemory getMemoryCache(AddressSpace space) {
		GadpClientTargetMemory memory = (GadpClientTargetMemory) proxy;
		if (memCache == null) {
			memCache = new HashMap<>();
		}
		return memCache.computeIfAbsent(space,
			s -> new CachedMemory(memory.getRawReader(s), memory.getRawWriter(s)));
	}

	protected synchronized void clearMemCacheEntries() {
		if (memCache == null) {
			return;
		}
		for (CachedMemory mem : memCache.values()) {
			mem.clear();
		}
	}

	protected synchronized Map<String, byte[]> getRegisterCache() {
		if (regCache == null) {
			regCache = Collections.synchronizedMap(new HashMap<>());
		}
		return regCache;
	}

	protected synchronized void clearRegisterCacheEntries() {
		if (regCache != null) {
			regCache.clear();
		}
	}

	protected synchronized ListenerSet<TargetBreakpointAction> getActions(boolean createIfAbsent) {
		if (actions == null && createIfAbsent) {
			actions = new ListenerSet<>(TargetBreakpointAction.class) {
				// Want strong references on actions
				protected Map<TargetBreakpointAction, TargetBreakpointAction> createMap() {
					return Collections.synchronizedMap(new LinkedHashMap<>());
				};
			};
		}
		return actions;
	}
}
