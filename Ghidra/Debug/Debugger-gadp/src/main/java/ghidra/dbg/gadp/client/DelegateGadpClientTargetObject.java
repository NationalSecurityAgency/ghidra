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
import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.gadp.GadpRegistry;
import ghidra.dbg.gadp.client.annot.GadpEventHandler;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.gadp.protocol.Gadp.EventNotification.EvtCase;
import ghidra.dbg.memory.CachedMemory;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointAction;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.program.model.address.AddressSpace;
import ghidra.util.Msg;
import ghidra.util.datastruct.ListenerSet;
import utilities.util.ProxyUtilities;

/**
 * This class is meant to be used as a delegate to a composed proxy
 */
public class DelegateGadpClientTargetObject
		extends DefaultTargetObject<GadpClientTargetObject, GadpClientTargetObject>
		implements GadpClientTargetObject {
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

	protected static final MethodHandles.Lookup LOOKUP = MethodHandles.lookup();
	protected static final Map<Set<Class<? extends TargetObject>>, GadpEventHandlerMap> EVENT_HANDLER_MAPS_BY_COMPOSITION =
		new HashMap<>();

	protected static GadpClientTargetObject makeModelProxy(GadpClient client,
			GadpClientTargetObject parent, String key, String typeHint, List<String> ifaceNames) {
		List<Class<? extends TargetObject>> ifaces = TargetObject.getInterfacesByName(ifaceNames);
		List<Class<? extends TargetObject>> mixins = GadpRegistry.getMixins(ifaces);
		TargetObjectSchema schema =
			parent == null ? client.getRootSchema() : parent.getSchema().getChildSchema(key);
		return new DelegateGadpClientTargetObject(client, parent, key, typeHint, schema, ifaceNames,
			ifaces, mixins).getProxy();
	}

	private final GadpClient client;
	private final List<String> ifaceNames;
	private final List<Class<? extends TargetObject>> ifaces;
	private final GadpEventHandlerMap eventHandlers;

	protected Map<AddressSpace, CachedMemory> memCache = null; // Becomes active if this is a TargetMemory
	protected Map<String, byte[]> regCache = null; // Becomes active if this is a TargtRegisterBank
	protected ListenerSet<TargetBreakpointAction> actions = null; // Becomes active is this is a TargetBreakpointSpec

	public DelegateGadpClientTargetObject(GadpClient client, GadpClientTargetObject parent,
			String key, String typeHint, TargetObjectSchema schema, List<String> ifaceNames,
			List<Class<? extends TargetObject>> ifaces,
			List<Class<? extends TargetObject>> mixins) {
		super(client, mixins, client, parent, key, typeHint, schema);
		this.client = client;
		this.ifaceNames = ifaceNames;
		this.ifaces = ifaces;

		Set<Class<? extends TargetObject>> allMixins = new HashSet<>(mixins);
		allMixins.add(GadpClientTargetObject.class);
		this.eventHandlers = EVENT_HANDLER_MAPS_BY_COMPOSITION.computeIfAbsent(allMixins,
			GadpEventHandlerMap::new);
	}

	@Override
	public GadpClient getModel() {
		return client;
	}

	@Override
	public GadpClientTargetObject getProxy() {
		return (GadpClientTargetObject) super.getProxy();
	}

	@Override
	public Collection<String> getInterfaceNames() {
		return ifaceNames;
	}

	@Override
	public Collection<? extends Class<? extends TargetObject>> getInterfaces() {
		return ifaces;
	}

	@Override
	public CompletableFuture<Void> resync(boolean attributes, boolean elements) {
		return client.sendChecked(Gadp.ResyncRequest.newBuilder()
				.setPath(GadpValueUtils.makePath(path))
				.setAttributes(attributes)
				.setElements(elements),
			Gadp.ResyncReply.getDefaultInstance()).thenApply(rep -> null);
	}

	@Override
	protected CompletableFuture<Void> requestAttributes(boolean refresh) {
		return resync(refresh, false);
	}

	@Override
	protected CompletableFuture<Void> requestElements(boolean refresh) {
		return resync(false, refresh);
	}

	@Override
	public DelegateGadpClientTargetObject getDelegate() {
		return this;
	}

	public void updateWithDeltas(Gadp.ModelObjectDelta deltaE, Gadp.ModelObjectDelta deltaA) {
		Map<String, GadpClientTargetObject> elementsAdded =
			GadpValueUtils.getElementMap(this, deltaE.getAddedList());
		Map<String, Object> attributesAdded =
			GadpValueUtils.getAttributeMap(this, deltaA.getAddedList());

		changeElements(deltaE.getRemovedList(), List.of(), elementsAdded, "Updated");
		changeAttributes(deltaA.getRemovedList(), attributesAdded, "Updated");
	}

	protected void handleEvent(Gadp.EventNotification notify) {
		eventHandlers.handle(getProxy(), notify.getEvtCase(), notify);
	}

	protected void assertValid() {
		if (!valid) {
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
		return client.sendChecked(Gadp.CacheInvalidateRequest.newBuilder()
				.setPath(GadpValueUtils.makePath(path)),
			Gadp.CacheInvalidateReply.getDefaultInstance()).thenApply(rep -> null);
	}

	protected synchronized CachedMemory getMemoryCache(AddressSpace space) {
		GadpClientTargetMemory memory = (GadpClientTargetMemory) getProxy();
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

	@Override
	public void doInvalidate(TargetObject branch, String reason) {
		client.removeProxy(path, reason);
		super.doInvalidate(branch, reason);
	}
}
