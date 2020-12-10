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

import java.lang.invoke.MethodHandles;
import java.lang.ref.Cleaner;
import java.lang.ref.Cleaner.Cleanable;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.manager.*;
import agent.dbgeng.manager.breakpoint.DbgBreakpointInfo;
import agent.dbgeng.model.iface1.*;
import agent.dbgeng.model.iface2.*;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.ModelObjectKind;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointAction;
import ghidra.dbg.util.PathUtils;
import ghidra.util.datastruct.ListenerSet;
import utilities.util.ProxyUtilities;

public class DelegateDbgModel2TargetObject extends DbgModel2TargetObjectImpl implements //
		DbgModelTargetAccessConditioned<DelegateDbgModel2TargetObject>, //
		DbgModelTargetExecutionStateful<DelegateDbgModel2TargetObject>, //
		DbgModelTargetBptHelper {
	// Probably don-t need any of the handler-map or annotation stuff

	protected final DbgStateListener accessListener = this::checkExited;

	protected static String indexObject(ModelObject obj) {
		return obj.getSearchKey();
	}

	public static String keyObject(ModelObject obj) {
		return PathUtils.makeKey(indexObject(obj));
	}

	protected static final Cleaner CLEANER = Cleaner.create();

	// For resource management, I highly recommend keeping the ProxyState stuff.
	// It's contents will look different
	protected static class ProxyState implements Runnable {
		protected final DbgModel2Impl model;
		protected final ModelObject modelObject;

		public ProxyState(DbgModel2Impl model, ModelObject modelObject) {
			this.model = model;
			this.modelObject = modelObject;
		}

		@Override
		public void run() {
			modelObject.dereference(); // Or whatever COM thing to free it here
		}
	}

	protected static Class<? extends DbgModelTargetObject> lookupWrapperType(String type,
			String parentName) {
		switch (type) {
			case "Available":
				return DbgModelTargetAvailableContainer.class;
			case "Sessions":
				return DbgModelTargetSessionContainer.class;
			case "Processes":
				return DbgModelTargetProcessContainer.class;
			case "Threads":
				return DbgModelTargetThreadContainer.class;
			case "Modules":
				return DbgModelTargetModuleContainer.class;
			case "Frames":
				return DbgModelTargetStack.class;
			case "Registers":
				return DbgModelTargetRegisterContainer.class;
			case "Attributes":
				return DbgModelTargetSessionAttributes.class;
			case "Breakpoints":
				return DbgModelTargetBreakpointContainer.class;
			case "cursession":
				return DbgModelTargetSession.class;
			case "curprocess":
				return DbgModelTargetProcess.class;
			case "curthread":
				return DbgModelTargetThread.class;
			case "curframe":
				return DbgModelTargetStackFrame.class;
			case "User":
				return DbgModelTargetRegisterBank.class;
			case "TTD":
				return DbgModelTargetTTD.class;
		}
		if (parentName != null) {
			switch (parentName) {
				case "Available":
					return DbgModelTargetAvailable.class;
				case "Sessions":
					return DbgModelTargetSession.class;
				case "Processes":
					return DbgModelTargetProcess.class;
				case "Threads":
					return DbgModelTargetThread.class;
				case "Modules":
					return DbgModelTargetModule.class;
				case "Frames":
					return DbgModelTargetStackFrame.class;
				case "Breakpoints":
					return DbgModelTargetBreakpointSpec.class;
				//case "Registers":
				//	return DbgModelTargetRegisterBank.class;
				case "FloatingPoint":
				case "Kernel":
				case "SIMD":
				case "VFP":
				case "User":
					return DbgModelTargetRegister.class;
			}
		}
		return null;
	}

	public static DbgModelTargetObject makeProxy(DbgModel2Impl model, DbgModelTargetObject parent,
			String key, ModelObject object) {
		List<Class<? extends TargetObject>> mixins = new ArrayList<>();
		String lkey = key;
		String pname = parent.getName();
		if (object.getKind().equals(ModelObjectKind.OBJECT_METHOD) || lkey.contains(")")) {
			mixins.add(DbgModelTargetMethod.class);
			// NB: We're passing the parent's mixin model to the method on the assumption
			//  the init methods will need to know that the method's children have various
			//  properties.
			lkey = pname;
			pname = "";
		}
		Class<? extends DbgModelTargetObject> mixin = lookupWrapperType(lkey, pname);
		if (mixin != null) {
			mixins.add(mixin);
		}
		return new DelegateDbgModel2TargetObject(model, parent, key, object, mixins).proxy;
	}

	private static Map<DbgModelTargetObject, DelegateDbgModel2TargetObject> map = new HashMap<>();

	public static DelegateDbgModel2TargetObject getDelegate(DbgModelTargetObject proxy) {
		return map.get(proxy);
	}

	protected static final MethodHandles.Lookup LOOKUP = MethodHandles.lookup();

	// NOTE: The Cleanable stuff is the replacement for overriding Object.finalize(), which
	// is now deprecated.
	protected final ProxyState state;
	protected final Cleanable cleanable;

	private final DbgModelTargetObject proxy;

	private boolean breakpointEnabled;
	private final ListenerSet<TargetBreakpointAction> breakpointActions =
		new ListenerSet<>(TargetBreakpointAction.class) {
			// Use strong references on actions
			protected Map<TargetBreakpointAction, TargetBreakpointAction> createMap() {
				return Collections.synchronizedMap(new LinkedHashMap<>());
			};
		};

	// Extending DefaultTargetObject may spare you from listeners, elements, and attributes
	//protected final ListenerSet<TargetObjectListener> listeners =
	//	new ListenerSet<>(TargetObjectListener.class);

	// any other fields you need to support your impl

	public DelegateDbgModel2TargetObject(DbgModel2Impl model, DbgModelTargetObject parent,
			String key, ModelObject modelObject, List<Class<? extends TargetObject>> mixins) {
		super(model, parent.getProxy(), key, getHintForObject(modelObject));
		this.state = new ProxyState(model, modelObject);
		this.cleanable = CLEANER.register(this, state);

		getManager().addStateListener(accessListener);

		this.proxy =
			ProxyUtilities.composeOnDelegate(DbgModelTargetObject.class, this, mixins, LOOKUP);
		map.put(proxy, this);
		if (proxy instanceof DbgEventsListener) {
			model.getManager().addEventsListener((DbgEventsListener) proxy);
		}
		setModelObject(modelObject);
	}

	@Override
	public <T extends TypedTargetObject<T>> T as(Class<T> iface) {
		return DebuggerObjectModel.requireIface(iface, proxy, getPath());
	}

	@Override
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public CompletableFuture<? extends DelegateDbgModel2TargetObject> fetch() {
		return (CompletableFuture) CompletableFuture.completedFuture(proxy);
	}

	@Override
	public TargetObject getProxy() {
		return proxy;
	}

	@SuppressWarnings("unchecked")
	@Override
	public CompletableFuture<? extends DelegateDbgModel2TargetObject> fetchParent() {
		TargetObjectRef p = getParent();
		if (p == null) {
			return AsyncUtils.nil();
		}
		return (CompletableFuture<? extends DelegateDbgModel2TargetObject>) p.fetch();
	}

	protected static String getHintForObject(ModelObject obj) {
		ModelObjectKind kind = obj.getKind();
		String ret = kind == null ? "" : kind.name();
		if (kind.equals(ModelObjectKind.OBJECT_INTRINSIC)) {
			ret += " " + obj.getValueString();
		}
		return ret;
	}

	protected void checkExited(DbgState state, DbgCause cause) {
		TargetExecutionState exec = TargetExecutionState.INACTIVE;
		switch (state) {
			case NOT_STARTED: {
				exec = TargetExecutionState.INACTIVE;
				break;
			}
			case STARTING: {
				exec = TargetExecutionState.ALIVE;
				break;
			}
			case RUNNING: {
				exec = TargetExecutionState.RUNNING;
				resetModified();
				onRunning();
				break;
			}
			case STOPPED: {
				exec = TargetExecutionState.STOPPED;
				onStopped();
				break;
			}
			case EXIT: {
				exec = TargetExecutionState.TERMINATED;
				onExit();
				break;
			}
		}
		if (proxy instanceof TargetExecutionStateful) {
			setExecutionState(exec, "Refreshed");
		}
	}

	private void invalidate() {
		if (proxy instanceof DbgModelTargetMemoryContainer || //
			proxy instanceof DbgModelTargetBreakpointContainer || //
			proxy instanceof DbgModelTargetRegisterContainer || //
			proxy instanceof DbgModelTargetRegisterBank || //
			proxy instanceof DbgModelTargetStackFrame || //
			proxy instanceof DbgModelTargetStack || //
			proxy instanceof DbgModelTargetTTD) {
			listeners.fire.invalidateCacheRequested(proxy);
			return;
		}
	}

	private void update() {
		if (proxy instanceof DbgModelTargetProcessContainer || //
			proxy instanceof DbgModelTargetThreadContainer || //
			proxy instanceof DbgModelTargetModuleContainer || //
			proxy instanceof DbgModelTargetBreakpointContainer || //
			proxy instanceof DbgModelTargetRegisterContainer || //
			proxy instanceof DbgModelTargetRegisterBank || //
			proxy instanceof DbgModelTargetStack || //
			proxy instanceof DbgModelTargetTTD) {
			requestElements(true);
			requestAttributes(true);
			return;
		}
		if (proxy instanceof DbgModelTargetRegister || proxy instanceof DbgModelTargetStackFrame) {
			DbgThread thread = proxy.getParentThread().getThread();
			if (thread.equals(getManager().getEventThread())) {
				requestAttributes(true);
			}
			return;
		}
	}

	public void onRunning() {
		invalidate();
		setAccessibility(TargetAccessibility.INACCESSIBLE);
	}

	public void onStopped() {
		setAccessibility(TargetAccessibility.ACCESSIBLE);
		update();
	}

	public void onExit() {
		setAccessibility(TargetAccessibility.ACCESSIBLE);
	}

	@Override
	public TargetAccessibility getAccessibility() {
		return accessibility;
	}

	@Override
	public void setAccessibility(TargetAccessibility accessibility) {
		synchronized (attributes) {
			if (this.accessibility == accessibility) {
				return;
			}
			this.accessibility = accessibility;
		}
		if (proxy instanceof TargetAccessConditioned) {
			changeAttributes(List.of(), List.of(), Map.of( //
				TargetAccessConditioned.ACCESSIBLE_ATTRIBUTE_NAME,
				accessibility == TargetAccessibility.ACCESSIBLE //
			), "Accessibility changed");
		}
	}

	// Methods required for DbgModelTargetBreakpointSpec mixin

	@Override
	public DbgBreakpointInfo getBreakpointInfo() {
		return bptInfoMap.get(Integer.decode(bptId));
	}

	@Override
	public void setBreakpointId(String id) {
		this.bptId = id;
	}

	@Override
	public void setBreakpointInfo(DbgBreakpointInfo info) {
		TargetObject id = (TargetObject) this.getCachedAttribute("Id");
		String idstr = id.getCachedAttribute(VALUE_ATTRIBUTE_NAME).toString();
		bptInfoMap.put(Integer.decode(idstr), info);
	}

	@Override
	public boolean isBreakpointEnabled() {
		return breakpointEnabled;
	}

	@Override
	public void setBreakpointEnabled(boolean enabled) {
		update();
		this.breakpointEnabled = enabled;
	}

	public ListenerSet<TargetBreakpointAction> getActions() {
		return breakpointActions;
	}

}
