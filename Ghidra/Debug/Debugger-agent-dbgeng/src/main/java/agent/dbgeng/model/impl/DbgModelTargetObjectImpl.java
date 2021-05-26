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
package agent.dbgeng.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.manager.*;
import agent.dbgeng.model.AbstractDbgModel;
import agent.dbgeng.model.iface1.DbgModelTargetAccessConditioned;
import agent.dbgeng.model.iface1.DbgModelTargetExecutionStateful;
import agent.dbgeng.model.iface2.*;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.schema.TargetObjectSchema;

public class DbgModelTargetObjectImpl extends DefaultTargetObject<TargetObject, TargetObject>
		implements DbgModelTargetObject {

	protected boolean accessible = true;
	protected final DbgStateListener accessListener = this::checkExited;
	private boolean modified;

	public DbgModelTargetObjectImpl(AbstractDbgModel impl, TargetObject parent, String name,
			String typeHint) {
		super(impl, parent, name, typeHint);
		getManager().addStateListener(accessListener);
	}

	public DbgModelTargetObjectImpl(AbstractDbgModel impl, TargetObject parent, String name,
			String typeHint, TargetObjectSchema schema) {
		super(impl, parent, name, typeHint, schema);
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
		if (this instanceof DbgModelTargetAccessConditioned) {
			changeAttributes(List.of(), List.of(), Map.of( //
				TargetAccessConditioned.ACCESSIBLE_ATTRIBUTE_NAME, accessible //
			), "Accessibility changed");
		}
	}

	@Override
	public AbstractDbgModel getModel() {
		return (AbstractDbgModel) model;
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
				if (getParentProcess() != null || this instanceof TargetProcess) {
					getManager().removeStateListener(accessListener);
				}
				onExit();
				break;
			}
			case SESSION_EXIT: {
				getModel().close();
				return;
			}
		}
		if (this instanceof DbgModelTargetExecutionStateful) {
			DbgModelTargetExecutionStateful stateful = (DbgModelTargetExecutionStateful) this;
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
	public DbgModelTargetSession getParentSession() {
		DbgModelTargetObject test = (DbgModelTargetObject) parent;
		while (test != null && !(test instanceof DbgModelTargetSession)) {
			test = (DbgModelTargetObject) test.getParent();
		}
		return test == null ? null : (DbgModelTargetSession) test;
	}

	@Override
	public DbgModelTargetProcess getParentProcess() {
		DbgModelTargetObject test = (DbgModelTargetObject) parent;
		while (test != null && !(test instanceof TargetProcess)) {
			test = (DbgModelTargetObject) test.getParent();
		}
		return test == null ? null : (DbgModelTargetProcess) test;
	}

	@Override
	public DbgModelTargetThread getParentThread() {
		DbgModelTargetObject test = (DbgModelTargetObject) parent;
		while (test != null && !(test instanceof TargetThread)) {
			test = (DbgModelTargetObject) test.getParent();
		}
		return test == null ? null : (DbgModelTargetThread) test;
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

}
