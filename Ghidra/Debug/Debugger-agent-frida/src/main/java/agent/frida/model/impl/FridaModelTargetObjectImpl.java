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
package agent.frida.model.impl;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.frida.frida.FridaClient;
import agent.frida.manager.FridaCause;
import agent.frida.manager.FridaStateListener;
import agent.frida.manager.FridaState;
import agent.frida.model.AbstractFridaModel;
import agent.frida.model.iface1.FridaModelTargetAccessConditioned;
import agent.frida.model.iface1.FridaModelTargetExecutionStateful;
import agent.frida.model.iface2.FridaModelTargetObject;
import agent.frida.model.iface2.FridaModelTargetProcess;
import agent.frida.model.iface2.FridaModelTargetSession;
import agent.frida.model.iface2.FridaModelTargetThread;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetAccessConditioned;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.target.TargetThread;
import ghidra.dbg.target.schema.TargetObjectSchema;

public class FridaModelTargetObjectImpl extends DefaultTargetObject<TargetObject, TargetObject>
		implements FridaModelTargetObject {

	protected boolean accessible = true;
	protected final FridaStateListener accessListener = this::checkExited;
	private boolean modified;

	private Object modelObject;
	protected Map<Object, TargetObject> objectMap = new HashMap<>();

	public FridaModelTargetObjectImpl(AbstractFridaModel impl, TargetObject parent, String name,
			String typeHint) {
		super(impl, parent, name, typeHint);
		this.setModelObject(((FridaModelTargetObject) parent).getModelObject());
		getManager().addStateListener(accessListener);
	}

	public FridaModelTargetObjectImpl(AbstractFridaModel impl, TargetObject parent, String name,
			Object modelObject,
			String typeHint) {
		super(impl, parent, name, typeHint);
		//((FridaModelTargetObject) parent).addMapObject(modelObject, this);
		this.setModelObject(modelObject);
		getManager().addStateListener(accessListener);
	}

	public FridaModelTargetObjectImpl(AbstractFridaModel impl, TargetObject parent, String name,
			Object modelObject,
			String typeHint, TargetObjectSchema schema) {
		super(impl, parent, name, typeHint, schema);
		this.setModelObject(modelObject);
		getManager().addStateListener(accessListener);
	}

	public void setAttribute(String key, String value) {
		changeAttributes(List.of(), List.of(), Map.of( //
			key, value), "Initialized");
	}

	@Override
	protected void doInvalidate(TargetObject branch, String reason) {
		super.doInvalidate(branch, reason);
		getManager().removeStateListener(accessListener);
	}

	public void setAccessible(boolean accessible) {
		synchronized (attributes) {
			if (this.accessible == accessible) {
				return;
			}
			this.accessible = accessible;
		}
		if (this instanceof FridaModelTargetAccessConditioned) {
			changeAttributes(List.of(), List.of(), Map.of( //
				TargetAccessConditioned.ACCESSIBLE_ATTRIBUTE_NAME, accessible //
			), "Accessibility changed");
		}
	}

	@Override
	public AbstractFridaModel getModel() {
		return (AbstractFridaModel) model;
	}

	public void onRunning() {
		setAccessible(false);
	}

	public void onStopped() {
		setAccessible(true);
	}

	public void onExit() {
		setAccessible(true);
	}

	protected void checkExited(FridaState state, FridaCause cause) {
		TargetExecutionState exec = TargetExecutionState.INACTIVE;
		switch (state) {
			case FRIDA_THREAD_WAITING: 
			{
				exec = TargetExecutionState.INACTIVE;
				break;
			}
			case FRIDA_THREAD_UNINTERRUPTIBLE: 
			{
				exec = TargetExecutionState.ALIVE;
				break;
			}
			case FRIDA_THREAD_STOPPED: { 
				exec = TargetExecutionState.STOPPED;
				onStopped();
				break;
			}
			case FRIDA_THREAD_RUNNING:
			{
				exec = TargetExecutionState.RUNNING;
				resetModified();
				onRunning();
				break;
			}
			case FRIDA_THREAD_HALTED: { 
				exec = TargetExecutionState.TERMINATED;
				if (getParentProcess() != null || this instanceof TargetProcess) {
					getManager().removeStateListener(accessListener);
				}
				onExit();
				break;
			}
		}
		if (this instanceof FridaModelTargetExecutionStateful) {
			FridaModelTargetExecutionStateful stateful = (FridaModelTargetExecutionStateful) this;
			stateful.setExecutionState(exec, "Refreshed");
		}
	}

	@Override
	public CompletableFuture<? extends Map<String, ?>> requestNativeAttributes() {
		throw new AssertionError();  // shouldn't ever be here
	}

	@Override
	public CompletableFuture<List<TargetObject>> requestNativeElements() {
		throw new AssertionError();  // shouldn't ever be here
	}

	@Override
	public FridaModelTargetSession getParentSession() {
		FridaModelTargetObject test = (FridaModelTargetObject) parent;
		while (test != null && !(test instanceof FridaModelTargetSession)) {
			test = (FridaModelTargetObject) test.getParent();
		}
		return test == null ? null : (FridaModelTargetSession) test;
	}

	@Override
	public FridaModelTargetProcess getParentProcess() {
		FridaModelTargetObject test = (FridaModelTargetObject) parent;
		while (test != null && !(test instanceof TargetProcess)) {
			test = (FridaModelTargetObject) test.getParent();
		}
		return test == null ? null : (FridaModelTargetProcess) test;
	}

	@Override
	public FridaModelTargetThread getParentThread() {
		FridaModelTargetObject test = (FridaModelTargetObject) parent;
		while (test != null && !(test instanceof TargetThread)) {
			test = (FridaModelTargetObject) test.getParent();
		}
		return test == null ? null : (FridaModelTargetThread) test;
	}

	@Override
	public void setModified(Map<String, Object> map, boolean b) {
		if (modified) {
			map.put(MODIFIED_ATTRIBUTE_NAME, modified);
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
		changeAttributes(List.of(), List.of(), Map.of( //
			MODIFIED_ATTRIBUTE_NAME, false //
		), "Refreshed");
	}

	public TargetObject searchForSuitable(Class<? extends TargetObject> type) {
		List<String> pathToClass = model.getRootSchema().searchForSuitable(type, path);
		return model.getModelObject(pathToClass);
	}

	public String getDescription(int level) {
		return getName();
	}

	@Override
	public Object getModelObject() {
		return modelObject;
	}

	@Override
	public void setModelObject(Object modelObject) {
		if (modelObject != null) {
			((FridaModelTargetObject) parent).addMapObject(modelObject, this);
		}
		this.modelObject = modelObject;
	}

	@Override
	public void addMapObject(Object object, TargetObject targetObject) {
		if (object == null) {
			return;
		}
		objectMap.put(FridaClient.getModelKey(object), targetObject);
	}

	@Override
	public TargetObject getMapObject(Object object) {
		if (object == null) {
			return null;
		}
		return objectMap.get(FridaClient.getModelKey(object));
	}

	@Override
	public void deleteMapObject(Object object) {
		if (object == null) {
			return;
		}
		objectMap.remove(FridaClient.getModelKey(object));
	}

}
