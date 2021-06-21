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
package agent.dbgmodel.model.impl;

import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.dbgeng.manager.DbgEventsListener;
import agent.dbgeng.manager.DbgStateListener;
import agent.dbgeng.manager.breakpoint.DbgBreakpointInfo;
import agent.dbgeng.model.AbstractDbgModel;
import agent.dbgeng.model.iface1.DbgModelSelectableObject;
import agent.dbgeng.model.iface2.*;
import agent.dbgeng.model.impl.*;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.ModelObjectKind;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.TypeKind;
import agent.dbgmodel.manager.DbgManager2Impl;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.PathUtils;
import ghidra.dbg.util.PathUtils.TargetObjectKeyComparator;
import ghidra.util.Msg;
import ghidra.util.datastruct.WeakValueHashMap;

public class DbgModel2TargetObjectImpl extends DefaultTargetObject<TargetObject, TargetObject>
		implements DbgModelTargetObject {

	protected final Map<String, TargetObject> elementsByKey = new WeakValueHashMap<>();

	protected DbgModelSelectableObject focus;
	public boolean accessible = true;

	private ModelObject modelObject = null;
	protected Map<String, Object> intrinsics = new TreeMap<>(TargetObjectKeyComparator.ATTRIBUTE);

	protected String bptId;
	protected static Map<Integer, DbgBreakpointInfo> bptInfoMap = new HashMap<>();

	protected String DBG_PROMPT = "(kd2)"; // Used by DbgModelTargetEnvironment

	protected static String indexObject(ModelObject obj) {
		return obj.getSearchKey();
	}

	public static String keyObject(ModelObject obj) {
		return PathUtils.makeKey(indexObject(obj));
	}

	protected static String getHintForObject(ModelObject obj) {
		TypeKind typeKind = obj.getTypeKind();
		return typeKind == null ? "" : typeKind.name();
	}

	public DbgModel2TargetObjectImpl(AbstractDbgModel model, TargetObject parent, String name,
			String typeHint) {
		super(model, parent, name, typeHint);
	}

	public DbgModel2TargetObjectImpl(AbstractDbgModel model, TargetObject parent, String name,
			String typeHint, TargetObjectSchema schema) {
		super(model, parent, name, typeHint, schema);
	}

	public <I> DbgModel2TargetObjectImpl(ProxyFactory<I> proxyFactory, I proxyInfo,
			AbstractDbgModel model, TargetObject parent, String name, String typeHint) {
		super(proxyFactory, proxyInfo, model, parent, name, typeHint);
	}

	@Override
	public DbgModel2Impl getModel() {
		return (DbgModel2Impl) super.getModel();
	}

	@Override
	public CompletableFuture<List<TargetObject>> requestNativeElements() {
		DbgManager2Impl manager2 = (DbgManager2Impl) getManager();
		List<String> pathX = PathUtils.extend(List.of("Debugger"), path);
		return manager2.listElements(pathX, this);
	}

	@Override
	public CompletableFuture<? extends Map<String, ?>> requestNativeAttributes() {
		DbgManager2Impl manager2 = (DbgManager2Impl) getManager();
		List<String> pathX = PathUtils.extend(List.of("Debugger"), path);
		return manager2.listAttributes(pathX, this);
	}

	@Override
	public CompletableFuture<Void> requestAugmentedAttributes() {
		return requestAttributes(false);
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		List<TargetObject> nlist = new ArrayList<>();
		List<String> rlist = new ArrayList<>();
		return requestNativeElements().thenCompose(list -> {
			synchronized (elements) {
				for (Entry<String, TargetObject> entry : elements.entrySet()) {
					TargetObject element = entry.getValue();
					if (!list.contains(element)) {
						if (element instanceof DbgStateListener) {
							getManager().removeStateListener((DbgStateListener) element);
						}
						if (element instanceof DbgEventsListener) {
							getManager().removeEventsListener((DbgEventsListener) element);
						}
						rlist.add(entry.getKey());
					}
				}
				nlist.addAll(list);
				return AsyncUtils.NIL;
				//return processModelObjectElements(nlist);
			}
		}).thenAccept(__ -> {
			changeElements(rlist, nlist, Map.of(), "Refreshed");
		});
	}

	protected boolean isReallyValid() {
		//synchronized (model.lock) {
		//System.out.println("checking validity: " + getJoinedPath(".") + "," +
		//	this.getDelegate().getClass());
		for (TargetObject p = this; p != null; p = p.getParent()) {
			//System.out.print("  .");
			if (!p.isValid()) {
				//System.out.println("x");
				return false;
			}
		}
		//System.out.println("_");
		//}
		return true;
	}

	@Override
	public CompletableFuture<Void> requestAttributes(boolean refresh) {
		Map<String, Object> nmap = new HashMap<>();
		List<String> rlist = new ArrayList<>();
		return requestNativeAttributes().thenCompose(map -> {
			synchronized (attributes) {
				if (map != null) {
					Collection<?> values = map.values();
					for (Entry<String, Object> entry : attributes.entrySet()) {
						Object attribute = entry.getValue();
						if (!values.contains(attribute)) {
							if (attribute instanceof DbgStateListener) {
								getManager().removeStateListener((DbgStateListener) attribute);
							}
							if (attribute instanceof DbgEventsListener) {
								getManager().removeEventsListener((DbgEventsListener) attribute);
							}
							rlist.add(entry.getKey());
						}
					}
					nmap.putAll(map);
				}
				return addModelObjectAttributes(nmap);
			}
		}).thenAccept(__ -> {
			// Meh
			if (!isReallyValid()) {
				return;
			}
			changeAttributes(List.of(), nmap, "Refreshed");
		});
	}

	protected CompletableFuture<Void> processModelObjectElements(List<TargetObject> list) {
		List<CompletableFuture<Void>> futures =
			list.stream().map(to -> processElement(to)).collect(Collectors.toList());
		CompletableFuture<Void> allOf =
			CompletableFuture.allOf(futures.toArray(new CompletableFuture[futures.size()]));
		return allOf;
	}

	private CompletableFuture<Void> processElement(TargetObject targetObject) {
		if (targetObject instanceof DbgModelTargetObject) {
			DbgModel2TargetProxy proxy = (DbgModel2TargetProxy) targetObject;
			DelegateDbgModel2TargetObject delegate = proxy.getDelegate();
			if (proxy instanceof TargetStackFrame || //
				proxy instanceof TargetModule || //
				proxy instanceof TargetBreakpointSpec) {
				return delegate.requestAttributes(false);
			}
		}
		return CompletableFuture.completedFuture(null);
	}

	protected CompletableFuture<Void> addModelObjectAttributes(Map<String, Object> attrs) {
		if (modelObject == null || !valid) {
			return CompletableFuture.completedFuture(null);
		}
		String key = modelObject.getSearchKey();
		ModelObjectKind kind = modelObject.getKind();
		TypeKind tk = modelObject.getTypeKind();
		String value = modelObject.getValueString();

		attrs.put(DISPLAY_ATTRIBUTE_NAME, key);
		if (kind != null) {
			attrs.put(KIND_ATTRIBUTE_NAME, kind.toString());
		}
		if (tk != null) {
			attrs.put(TYPE_ATTRIBUTE_NAME, tk.toString());
		}
		if (value != null && !value.equals("")) {
			attrs.put(VALUE_ATTRIBUTE_NAME, value);
			if (!kind.equals(ModelObjectKind.OBJECT_PROPERTY_ACCESSOR)) {
				synchronized (attributes) {
					String oldval = (String) attributes.get(DISPLAY_ATTRIBUTE_NAME);
					String newval = getName() + " : " + value;
					attrs.put(DISPLAY_ATTRIBUTE_NAME, newval);
					setModified(attrs, !newval.equals(oldval));
				}
			}
			if (tk == null) {
				Object val = modelObject.getIntrinsicValue();
				if (val != null) {
					attrs.put(TYPE_ATTRIBUTE_NAME, val.getClass().getSimpleName());
				}
			}
		}
		if (this instanceof DelegateDbgModel2TargetObject) {
			DelegateDbgModel2TargetObject delegate = (DelegateDbgModel2TargetObject) this;
			TargetObject proxy = delegate.getProxy();
			if (proxy instanceof TargetAccessConditioned) {
				attrs.put(TargetAccessConditioned.ACCESSIBLE_ATTRIBUTE_NAME, accessible);
			}
			if (proxy instanceof TargetExecutionStateful) {
				if (isValid()) {
					TargetExecutionStateful stateful = (TargetExecutionStateful) proxy;
					TargetExecutionState state = stateful.getExecutionState();
					attrs.put(TargetExecutionStateful.STATE_ATTRIBUTE_NAME, state);
				}
			}
			if (proxy instanceof TargetAttacher) {
				attrs.put(TargetAttacher.SUPPORTED_ATTACH_KINDS_ATTRIBUTE_NAME,
					DbgModelTargetProcessImpl.SUPPORTED_KINDS);
			}
			if (proxy instanceof TargetSteppable) {
				attrs.put(TargetSteppable.SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME,
					DbgModelTargetThreadImpl.SUPPORTED_KINDS);
			}
			if (proxy instanceof TargetInterpreter) {
				attrs.put(TargetInterpreter.PROMPT_ATTRIBUTE_NAME, DBG_PROMPT);
			}
			if (proxy instanceof TargetBreakpointSpecContainer) {
				attrs.put(TargetBreakpointSpecContainer.SUPPORTED_BREAK_KINDS_ATTRIBUTE_NAME,
					TargetBreakpointKindSet.of(TargetBreakpointKind.values()));
			}
			if (proxy instanceof TargetBreakpointSpec) {
				DbgModelTargetBreakpointSpec spec = (DbgModelTargetBreakpointSpec) proxy;
				return spec.init(attrs);
			}
			if (proxy instanceof TargetEnvironment) {
				attrs.put(TargetEnvironment.ARCH_ATTRIBUTE_NAME, "x86_64");
				attrs.put(TargetEnvironment.DEBUGGER_ATTRIBUTE_NAME, "dbgeng");
				attrs.put(TargetEnvironment.OS_ATTRIBUTE_NAME, "Windows");
				attrs.put(TargetEnvironment.ENDIAN_ATTRIBUTE_NAME, "little");
			}
			if (proxy instanceof TargetModule) {
				//attrs.put(TargetObject.ORDER_ATTRIBUTE_NAME,
				//	Integer.decode(modelObject.getOriginalKey()));
				DbgModelTargetModule module = (DbgModelTargetModule) proxy;
				return module.init(attrs);
			}
			if (proxy instanceof TargetProcess) {
				DbgModelTargetMemoryContainer memory;
				if (attributes.containsKey("Memory")) {
					memory = (DbgModelTargetMemoryContainer) attributes.get("Memory");
				}
				else {
					memory = new DbgModelTargetMemoryContainerImpl((DbgModelTargetProcess) proxy);
				}
				attrs.put(memory.getName(), memory);
				memory.requestElements(true);
			}
			if (proxy instanceof TargetThread) {
				DbgModelTargetThread targetThread = (DbgModelTargetThread) proxy;
				String executionType =
					targetThread.getThread().getExecutingProcessorType().description;
				attrs.put(TargetEnvironment.ARCH_ATTRIBUTE_NAME, executionType);
			}
			if (proxy instanceof TargetRegister) {
				DbgModelTargetObject bank = (DbgModelTargetObject) getParent();
				TargetObject container = bank.getParent();
				attrs.put(TargetRegister.CONTAINER_ATTRIBUTE_NAME, container);
			}
			if (proxy instanceof TargetRegisterBank) {
				attrs.put(TargetRegisterBank.DESCRIPTIONS_ATTRIBUTE_NAME, getParent());
			}
			if (proxy instanceof TargetStackFrame) {
				DbgModelTargetStackFrame frame = (DbgModelTargetStackFrame) proxy;
				return frame.init(attrs);
			}
			if (proxy instanceof DbgModelTargetTTD) {
				DbgModelTargetTTD ttd = (DbgModelTargetTTD) proxy;
				return ttd.init(attrs);
			}
		}

		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<?> fetchChild(final String key) {
		/* Would like to do this, but has some very bad effects
		return getModel().gateFuture(doFetchChild(key));
		}	
		public CompletableFuture<?> doFetchChild(final String key) {
		*/
		synchronized (elements) {
			if (key.startsWith("[") && key.endsWith("]")) {
				String trimKey = key.substring(1, key.length() - 1);
				if (elements.containsKey(trimKey)) {
					return CompletableFuture.completedFuture(elements.get(trimKey));
				}
				return requestElements(false).thenApply(__ -> getCachedElements().get(trimKey));
			}
		}
		synchronized (attributes) {
			if (attributes.containsKey(key)) {
				return CompletableFuture.completedFuture(attributes.get(key));
			}
			if (key.endsWith(")")) {
				DbgManager2Impl manager2 = (DbgManager2Impl) getManager();
				List<String> pathX = PathUtils.extend(List.of("Debugger"), path);
				pathX = PathUtils.extend(pathX, key);
				return manager2.applyMethods(pathX, this).thenApply(obj -> {
					changeAttributes(List.of(), List.of(), Map.of( //
						key, obj //
					), "Initialized");
					return obj;
				});
			}
			return requestAttributes(false).thenApply(__ -> getCachedAttribute(key));
		}
	}

	//@Override
	//public TargetAccessibility getAccessibility() {
	//	return accessibility;
	//}

	public DbgModelSelectableObject getFocus() {
		return focus;
	}

	public Map<String, Object> getIntrinsics() {
		return intrinsics;
	}

	public void setModelObject(ModelObject modelObject) {
		this.modelObject = modelObject;
		Map<String, Object> attrs = new HashMap<>();
		addModelObjectAttributes(attrs).thenAccept(__ -> {
			if (isReallyValid() && !attrs.isEmpty()) {
				changeAttributes(List.of(), List.of(), attrs, "Refreshed");
			}
		}).exceptionally(ex -> {
			Msg.error(this, "Problem setting model object" + PathUtils.toString(getPath()) + ": ",
				ex);
			return null;
		});
	}

	@Override
	public void removeListener(DebuggerModelListener l) {
		listeners.remove(l);
	}

	@Override
	public DbgModelTargetSession getParentSession() {
		if (this instanceof DbgModelTargetSession) {
			return (DbgModelTargetSession) this;
		}
		DbgModelTargetObject test = (DbgModelTargetObject) parent;
		while (test != null && !(test.getProxy() instanceof DbgModelTargetSession)) {
			test = (DbgModelTargetObject) test.getParent();
		}
		return test == null ? null : (DbgModelTargetSession) test.getProxy();
	}

	@Override
	public DbgModelTargetProcess getParentProcess() {
		DbgModelTargetObject test = (DbgModelTargetObject) parent;
		while (test != null && !(test.getProxy() instanceof TargetProcess)) {
			test = (DbgModelTargetObject) test.getParent();
		}
		return test == null ? null : (DbgModelTargetProcess) test.getProxy();
	}

	@Override
	public DbgModelTargetThread getParentThread() {
		DbgModelTargetObject test = (DbgModelTargetObject) parent;
		while (test != null && !(test.getProxy() instanceof TargetThread)) {
			test = (DbgModelTargetObject) test.getParent();
		}
		return test == null ? null : (DbgModelTargetThread) test.getProxy();
	}

	@Override
	public void setModified(Map<String, Object> attrs, boolean modified) {
		if (modified) {
			attrs.put(MODIFIED_ATTRIBUTE_NAME, modified);
		}
	}

	@Override
	public void setModified(boolean modified) {
		if (modified) {
			changeAttributes(List.of(), List.of(), Map.of( //
				MODIFIED_ATTRIBUTE_NAME, modified //
			), "Refreshed");
		}
	}

	@Override
	public void resetModified() {
		if (getCachedAttribute(MODIFIED_ATTRIBUTE_NAME) != null) {
			changeAttributes(List.of(), List.of(), Map.of( //
				MODIFIED_ATTRIBUTE_NAME, false //
			), "Refreshed");
		}
	}

	/*
	protected static Set<Class<?>> dependencySet = Set.of(//
		TargetProcess.class, //
		TargetThread.class, //
		TargetStack.class, //
		TargetStackFrame.class, //
		TargetRegisterBank.class, //
		TargetRegisterContainer.class, //
		TargetRegister.class, //
		TargetMemory.class, //
		TargetMemoryRegion.class, //
		TargetModule.class, //
		TargetModuleContainer.class, //
		TargetSection.class, //
		TargetBreakpointContainer.class, //
		TargetBreakpointSpec.class, //
		TargetBreakpointLocation.class, //
		TargetEventScope.class, //
		TargetFocusScope.class, //
		TargetExecutionStateful.class //
	);
	
	private CompletableFuture<Void> findDependencies(TargetObjectListener l) {
		System.err.println("findDependencies " + this);
		Map<String, TargetObject> resultAttrs = new HashMap<>();
		Map<String, TargetObject> resultElems = new HashMap<>();
		AsyncFence fence = new AsyncFence();
		fence.include(fetchAttributes(false).thenCompose(attrs -> {
			AsyncFence af = new AsyncFence();
			for (String key : attrs.keySet()) { //requiredObjKeys) {
				Object object = attrs.get(key);
				if (!(object instanceof TargetObjectRef)) {
					continue;
				}
				TargetObjectRef ref = (TargetObjectRef) object;
				if (PathUtils.isLink(getPath(), key, ref.getPath())) {
					continue;
				}
				af.include(ref.fetch().thenAccept(obj -> {
					if (isDependency(obj)) {
						synchronized (this) {
							resultAttrs.put(key, obj);
							obj.addListener(l);
						}
					}
				}));
			}
			return af.ready();
		}));
		fence.include(fetchElements(false).thenCompose(elems -> {
			AsyncFence ef = new AsyncFence();
			for (Entry<String, ? extends TargetObjectRef> entry : elems.entrySet()) {
				ef.include(entry.getValue().fetch().thenAccept(obj -> {
					synchronized (this) {
						resultElems.put(entry.getKey(), obj);
						obj.addListener(l);
					}
				}));
			}
			return ef.ready();
		}));
		return fence.ready().thenAccept(__ -> {
			listeners.fire.attributesChanged(this, List.of(), resultAttrs);
			listeners.fire.elementsChanged(this, List.of(), resultElems);
		});
	}
	
	public boolean isDependency(TargetObject object) {
		String name = object.getName();
		if (name != null) {
			if (name.equals("Debug"))
				return true;
			if (name.equals("Stack"))
				return true;
		}
	
		Set<Class<? extends TargetObject>> interfaces = object.getSchema().getInterfaces();
		for (Class<? extends TargetObject> ifc : interfaces) {
			if (dependencySet.contains(ifc)) {
				return true;
			}
		}
		return false;
	}
	
	@Override
	public void addListener(TargetObjectListener l) {
		listeners.add(l);
		if (isDependency(this)) {
			findDependencies(l);
		}
	}
	*/
}
