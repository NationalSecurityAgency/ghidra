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

import agent.dbgeng.manager.*;
import agent.dbgeng.manager.breakpoint.DbgBreakpointInfo;
import agent.dbgeng.model.iface1.*;
import agent.dbgeng.model.iface2.*;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.ModelObjectKind;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointAction;
import ghidra.dbg.util.PathUtils;
import ghidra.util.datastruct.ListenerSet;

public class DelegateDbgModel2TargetObject extends DbgModel2TargetObjectImpl implements //
		DbgModelTargetAccessConditioned, //
		DbgModelTargetExecutionStateful, //
		DbgModel2TargetProxy, DbgModelTargetBptHelper {
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
			case "Debug":
				return DbgModelTargetDebugContainer.class;
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

		/*
		if (object.getKind().equals(ModelObjectKind.OBJECT_METHOD) || lkey.contains(")")) {
			mixins.add(DbgModelTargetMethod.class);
			// NB: We're passing the parent's mixin model to the method on the assumption
			//  the init methods will need to know that the method's children have various
			//  properties.
			lkey = pname;
			pname = "";
		}
		*/

		if (object.getKind().equals(ModelObjectKind.OBJECT_METHOD)) {
			mixins.add(DbgModelTargetMethod.class);
		}
		else {
			Class<? extends DbgModelTargetObject> mixin = lookupWrapperType(lkey, pname);
			if (mixin != null) {
				mixins.add(mixin);
			}
		}
		return new DelegateDbgModel2TargetObject(model, parent, key, object, mixins).getProxy();
	}

	protected static final MethodHandles.Lookup LOOKUP = MethodHandles.lookup();

	// NOTE: The Cleanable stuff is the replacement for overriding Object.finalize(), which
	// is now deprecated.
	protected final ProxyState state;
	protected final Cleanable cleanable;

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
		super(model, mixins, model, parent.getProxy(), key, getHintForObject(modelObject));
		//System.err.println(this);
		this.state = new ProxyState(model, modelObject);
		this.cleanable = CLEANER.register(this, state);

		getManager().addStateListener(accessListener);

		if (proxy instanceof DbgEventsListener) {
			model.getManager().addEventsListener((DbgEventsListener) proxy);
		}
		setModelObject(modelObject);
		init();
	}

	public DelegateDbgModel2TargetObject clone(String key, ModelObject modelObject) {
		DbgModelTargetObject p = (DbgModelTargetObject) getParent();
		List<Class<? extends TargetObject>> mixins = new ArrayList<>();
		Class<? extends DbgModelTargetObject> mixin = lookupWrapperType(key, p.getName());
		if (mixin != null) {
			mixins.add(mixin);
		}
		DelegateDbgModel2TargetObject delegate =
			new DelegateDbgModel2TargetObject(getModel(), p, key, modelObject, mixins);
		return delegate;
	}

	@Override
	public DbgModelTargetObject getProxy() {
		return (DbgModelTargetObject) proxy;
	}

	protected static String getHintForObject(ModelObject obj) {
		ModelObjectKind kind = obj.getKind();
		String ret = kind == null ? "" : kind.name();
		if (kind.equals(ModelObjectKind.OBJECT_INTRINSIC)) {
			ret += " " + obj.getValueString();
		}
		return ret;
	}

	@Override
	protected void doInvalidate(TargetObject branch, String reason) {
		super.doInvalidate(branch, reason);
		getManager().removeStateListener(accessListener);
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
			case SESSION_EXIT: {
				getModel().close();
				return;
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
			//listeners.fire.invalidateCacheRequested(proxy);
			return;
		}
	}

	public void init() {
		if (PathUtils.isLink(parent.getPath(), proxy.getName(), proxy.getPath())) {
			return;
		}
		if (proxy instanceof DbgModelTargetSession || //
			proxy instanceof DbgModelTargetProcess || //
			proxy instanceof DbgModelTargetThread) {
			requestAttributes(false);
			return;
		}
		if (proxy instanceof DbgModelTargetRegisterContainer || //
			proxy.getName().equals("Stack") ||
			proxy.getName().equals("Debug")) {
			requestAttributes(false);
			return;
		}
		if (proxy instanceof DbgModelTargetProcessContainer || //
			proxy instanceof DbgModelTargetThreadContainer || //
			proxy instanceof DbgModelTargetModuleContainer || //
			proxy instanceof DbgModelTargetBreakpointContainer || //
			proxy instanceof DbgModelTargetStack) {
			requestElements(false);
			return;
		}
	}

	public void onRunning() {
		invalidate();
		setAccessible(false);
	}

	public void onStopped() {
		setAccessible(true);
	}

	public void onExit() {
		setAccessible(true);
	}

	@Override
	public boolean isAccessible() {
		return accessible;
	}

	@Override
	public void setAccessible(boolean accessible) {
		synchronized (attributes) {
			if (this.accessible == accessible) {
				return;
			}
			this.accessible = accessible;
		}
		if (proxy instanceof TargetAccessConditioned) {
			changeAttributes(List.of(), List.of(), Map.of( //
				TargetAccessConditioned.ACCESSIBLE_ATTRIBUTE_NAME, accessible //
			), "Accessibility changed");
			DbgModelTargetAccessConditioned accessConditioned =
				(DbgModelTargetAccessConditioned) proxy;
		}
	}

	@Override
	public DelegateDbgModel2TargetObject getDelegate() {
		return this;
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
		this.breakpointEnabled = enabled;
	}

	@Override
	public ListenerSet<TargetBreakpointAction> getActions() {
		return breakpointActions;
	}

	public void threadStateChangedSpecific(DbgState state, DbgReason reason) {
		if (state.equals(DbgState.RUNNING)) {
			return;
		}
		if (proxy instanceof TargetThread) {
			List<DelegateDbgModel2TargetObject> delegates = new ArrayList<>();
			TargetObject stack =
				(TargetObject) getCachedAttribute("Stack");
			DbgModelTargetStack frames =
				(DbgModelTargetStack) stack.getCachedAttribute("Frames");
			delegates.add((DelegateDbgModel2TargetObject) frames.getDelegate());
			DbgModelTargetRegisterContainer container =
				(DbgModelTargetRegisterContainer) getCachedAttribute("Registers");
			delegates.add((DelegateDbgModel2TargetObject) container.getDelegate());
			DbgModelTargetRegisterBank bank =
				(DbgModelTargetRegisterBank) container.getCachedAttribute("User");
			delegates.add((DelegateDbgModel2TargetObject) bank.getDelegate());
			for (DelegateDbgModel2TargetObject delegate : delegates) {
				delegate.threadStateChangedSpecific(state, reason);
			}
		}
		if (proxy instanceof TargetRegisterContainer) {
			requestElements(false);
			requestAttributes(false);
		}
		if (proxy instanceof TargetRegisterBank) {
			TargetRegisterBank bank = (TargetRegisterBank) proxy;
			//requestElements(false);
			requestAttributes(false).thenAccept(__ -> {
				bank.readRegistersNamed(getCachedAttributes().keySet());
			});
		}
		if (proxy instanceof TargetStack) {
			requestAttributes(false);
			requestElements(false).thenAccept(__ -> {
				for (TargetObject obj : getCachedElements().values()) {
					if (obj instanceof TargetStackFrame) {
						DbgModelTargetObject frame = (DbgModelTargetObject) obj;
						DelegateDbgModel2TargetObject delegate =
							(DelegateDbgModel2TargetObject) frame.getDelegate();
						delegate.threadStateChangedSpecific(state, reason);
					}
				}
			});
		}
		if (proxy instanceof TargetStackFrame) {
			requestAttributes(false);
		}
	}
}
