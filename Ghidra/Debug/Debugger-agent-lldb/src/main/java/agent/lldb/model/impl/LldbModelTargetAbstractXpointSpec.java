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
package agent.lldb.model.impl;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import SWIG.SBBreakpointLocation;
import SWIG.SBTarget;
import agent.lldb.lldb.DebugClient;
import agent.lldb.model.iface2.*;
import ghidra.async.AsyncUtils;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "BreakpointSpec",
	elements = { //
		@TargetElementType(type = LldbModelTargetBreakpointLocationImpl.class) //
	},
	attributes = {
		@TargetAttributeType(name = "Type", type = String.class),
		@TargetAttributeType(name = "Valid", type = Boolean.class),
		@TargetAttributeType(name = "Enabled", type = Boolean.class),
		@TargetAttributeType(name = "Count", type = Long.class),
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public abstract class LldbModelTargetAbstractXpointSpec extends LldbModelTargetObjectImpl
		implements LldbModelTargetBreakpointSpec {

	protected static String keyBreakpoint(Object bpt) {
		return PathUtils.makeKey(DebugClient.getId(bpt));
	}

	protected long number;
	protected boolean enabled;
	protected String expression;
	protected String display;
	protected TargetBreakpointKindSet kinds;

	protected final Map<Integer, LldbModelTargetBreakpointLocation> breaksBySub =
		new WeakValueHashMap<>();
	protected final ListenerSet<TargetBreakpointAction> actions =
		new ListenerSet<>(TargetBreakpointAction.class) {
			// Use strong references on actions
			protected Map<TargetBreakpointAction, TargetBreakpointAction> createMap() {
				return Collections.synchronizedMap(new LinkedHashMap<>());
			};
		};

	public LldbModelTargetAbstractXpointSpec(LldbModelTargetBreakpointContainer breakpoints,
			Object info, String title) {
		super(breakpoints.getModel(), breakpoints, keyBreakpoint(info), info, title);

		changeAttributes(List.of(), Map.of(CONTAINER_ATTRIBUTE_NAME, breakpoints), "Initialized");
	}

	@Override
	public void setModelObject(Object modelObject) {
		super.setModelObject(modelObject);
		getModel().addModelObject(modelObject, this);
	}

	protected CompletableFuture<Void> init() {
		Object info = getModelObject();
		updateInfo(info, "Created");
		return AsyncUtils.NIL;
	}

	@Override
	public abstract String getDescription(int level);

	@Override
	public abstract void updateInfo(Object info, String reason);

	protected abstract TargetBreakpointKindSet computeKinds(Object from);

	protected abstract void updateAttributesFromInfo(String reason);

	@Override
	public CompletableFuture<Void> delete() {
		String id = DebugClient.getId(getModelObject());
		return getModel().gateFuture(getManager().deleteBreakpoints(id));
	}

	@Override
	public boolean isEnabled() {
		return enabled;
	}

	@Override
	public String getExpression() {
		return expression;
	}

	@Override
	public TargetBreakpointKindSet getKinds() {
		return kinds;
	}

	@Override
	public void addAction(TargetBreakpointAction action) {
		actions.add(action);
	}

	@Override
	public void removeAction(TargetBreakpointAction action) {
		actions.remove(action);
	}

	protected CompletableFuture<Object> getInfo(boolean refresh) {
		SBTarget session = getManager().getCurrentSession();
		String id = DebugClient.getId(getModelObject());
		if (!refresh) {
			return CompletableFuture
					.completedFuture(getManager().getKnownBreakpoints(session).get(id));
		}
		return getManager().listBreakpoints(session)
				.thenApply(__ -> getManager().getKnownBreakpoints(session).get(id));
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getInfo(refresh).thenAccept(i -> {
			updateInfo(i, "Refreshed");
		});
	}

	@Override
	public CompletableFuture<Void> disable() {
		String id = DebugClient.getId(getModelObject());
		return getModel().gateFuture(getManager().disableBreakpoints(id));
	}

	@Override
	public CompletableFuture<Void> enable() {
		String id = DebugClient.getId(getModelObject());
		return getModel().gateFuture(getManager().enableBreakpoints(id));
	}

	protected void breakpointHit(LldbModelTargetStackFrame frame,
			LldbModelTargetBreakpointLocation eb) {
		actions.fire.breakpointHit(this, frame.getParentThread(), frame, eb);
	}

	public synchronized LldbModelTargetBreakpointLocation getTargetBreakpointLocation(
			SBBreakpointLocation loc) {
		return breaksBySub.computeIfAbsent(loc.GetID(),
			i -> new LldbModelTargetBreakpointLocationImpl(this, loc));
	}

	@Override
	public String getDisplay() {
		return display;
	}

	@Override
	public void setEnabled(boolean enabled, String reason) {
		this.enabled = enabled;
	}

	@Override
	public ListenerSet<TargetBreakpointAction> getActions() {
		return new ListenerSet<TargetBreakpointAction>(null);
	}

}
