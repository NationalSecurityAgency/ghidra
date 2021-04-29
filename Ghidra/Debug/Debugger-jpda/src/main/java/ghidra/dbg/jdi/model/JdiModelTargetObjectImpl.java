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
package ghidra.dbg.jdi.model;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import com.sun.jdi.Mirror;
import com.sun.jdi.ThreadReference;

import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.jdi.manager.JdiCause;
import ghidra.dbg.jdi.manager.JdiStateListener;
import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils;

public class JdiModelTargetObjectImpl extends
		DefaultTargetObject<TargetObject, JdiModelTargetObject> implements JdiModelTargetObject {

	public static String keyObject(String id) {
		return PathUtils.makeKey(id);
	}

	protected final JdiModelImpl impl;
	protected final Mirror mirror;
	protected final Object object;
	protected String display;

	protected final JdiStateListener accessListener = this::checkExited;
	protected JdiModelTargetVM targetVM;
	private boolean modified;

	public JdiModelTargetObjectImpl(JdiModelTargetObject parent, String id) {
		super(parent.getModelImpl(), parent, id, "Object");
		this.impl = parent.getModelImpl();
		this.mirror = (Mirror) parent.getObject();
		this.object = null;
		this.display = id;

		if (mirror != null) {
			targetVM = impl.getTargetVM(mirror);
			targetVM.setTargetObject(parent + ":" + id, null, this);
		}

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, display = getDisplay() //
		), "Initialized");
	}

	public JdiModelTargetObjectImpl(JdiModelTargetObject parent, String id, Object object,
			boolean isElement) {
		super(parent.getModelImpl(), parent, isElement ? keyObject(id) : id, "Object");
		this.impl = parent.getModelImpl();
		this.mirror = object instanceof Mirror ? (Mirror) object : null;
		this.object = object;
		this.display = id;

		if (mirror != null) {
			if (this instanceof JdiModelTargetVM) {
				targetVM = (JdiModelTargetVM) this;
			}
			else {
				targetVM = impl.getTargetVM(mirror);
			}
			targetVM.setTargetObject(id, object == null ? id : object, this);
		}

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, display = getDisplay() //
		), "Initialized");
	}

	public JdiModelTargetObjectImpl(JdiModelTargetSectionContainer parent) {
		super(parent.getModelImpl(), parent, keyObject("NULL_SPACE"), "Object");
		this.impl = parent.getModelImpl();
		this.mirror = parent.mirror;
		this.display = "NULL_SPACE";
		this.object = display;
	}

	public CompletableFuture<Void> init() {
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public JdiModelImpl getModelImpl() {
		return impl;
	}

	@Override
	public String getDisplay() {
		return display;
	}

	@Override
	public Object getObject() {
		return object;
	}

	@Override
	public JdiModelTargetObject getTargetObject(Object obj) {
		if (targetVM != null) {
			return targetVM.getTargetObject(obj);
		}
		//System.err.println("Attempt to getTargetObject from class without Mirror " + this);
		return null;
	}

	protected void checkExited(Integer state, JdiCause cause) {
		switch (state) {
			case ThreadReference.THREAD_STATUS_NOT_STARTED: {
				break;
			}
			case ThreadReference.THREAD_STATUS_MONITOR: {
				break;
			}
			case ThreadReference.THREAD_STATUS_WAIT: {
				onStopped();
				break;
			}
			case ThreadReference.THREAD_STATUS_ZOMBIE: {
				break;
			}
			case ThreadReference.THREAD_STATUS_SLEEPING: {
				break;
			}
			case ThreadReference.THREAD_STATUS_RUNNING: {
				resetModified();
				onRunning();
				break;
			}
			case ThreadReference.THREAD_STATUS_UNKNOWN: {
				break;
			}
		}
	}

	protected void onRunning() {
		// Nothing to do here
	}

	protected void onStopped() {
		Map<String, ?> existingAttributes = getCachedAttributes();
		Boolean autoupdate = (Boolean) existingAttributes.get("autoupdate");
		if (autoupdate != null && autoupdate) {
			requestAttributes(true);
			requestElements(true);
		}
	}

	public void setModified(boolean modified) {
		if (modified) {
			changeAttributes(List.of(), List.of(), Map.of( //
				MODIFIED_ATTRIBUTE_NAME, modified //
			), "Refreshed");
		}
	}

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
