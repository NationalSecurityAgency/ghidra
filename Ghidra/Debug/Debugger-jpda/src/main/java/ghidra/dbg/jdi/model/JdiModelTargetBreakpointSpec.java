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

import java.util.*;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.jdi.manager.breakpoint.JdiBreakpointInfo;
import ghidra.dbg.jdi.model.iface1.JdiModelTargetDeletable;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.dbg.target.TargetBreakpointLocation;
import ghidra.dbg.target.TargetBreakpointSpec;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.util.datastruct.ListenerSet;

@TargetObjectSchemaInfo(
	name = "BreakpointSpec",
	attributes = {
		@TargetAttributeType(
			name = TargetBreakpointSpec.CONTAINER_ATTRIBUTE_NAME,
			type = JdiModelTargetBreakpointContainer.class),
		@TargetAttributeType(
			name = TargetBreakpointLocation.SPEC_ATTRIBUTE_NAME,
			type = JdiModelTargetBreakpointSpec.class),
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class JdiModelTargetBreakpointSpec extends JdiModelTargetObjectImpl
		implements TargetBreakpointSpec, JdiModelTargetDeletable {

	protected JdiBreakpointInfo info;
	protected TargetBreakpointKindSet kinds;

	protected final ListenerSet<TargetBreakpointAction> actions =
		new ListenerSet<>(TargetBreakpointAction.class) {
			// Use strong references on actions
			protected Map<TargetBreakpointAction, TargetBreakpointAction> createMap() {
				return Collections.synchronizedMap(new LinkedHashMap<>());
			}
		};

	public JdiModelTargetBreakpointSpec(JdiModelTargetBreakpointContainer breakpoints,
			JdiBreakpointInfo info, boolean isElement) {
		super(breakpoints, info.toString(), info, isElement);
	}

	@Override
	public CompletableFuture<Void> delete() {
		info.setEnabled(false);
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public boolean isEnabled() {
		return info.isEnabled();
	}

	@Override
	public String getExpression() {
		return "";
	}

	protected TargetBreakpointKindSet computeKinds(JdiBreakpointInfo from) {
		switch (from.getType()) {
			case BREAKPOINT:
				return TargetBreakpointKindSet.of(TargetBreakpointKind.SW_EXECUTE);
			case MODIFICATION_WATCHPOINT:
				return TargetBreakpointKindSet.of(TargetBreakpointKind.WRITE);
			case ACCESS_WATCHPOINT:
				return TargetBreakpointKindSet.of(TargetBreakpointKind.READ,
					TargetBreakpointKind.WRITE);
			default:
				return TargetBreakpointKindSet.of();
		}
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

	protected CompletableFuture<JdiBreakpointInfo> getInfo(boolean refresh) {
		return CompletableFuture.completedFuture(info);
	}

	protected void updateAttributesFromInfo(String reason) {
		boolean enabled = info.isEnabled();

		changeAttributes(List.of(), List.of(), Map.of( //
			ENABLED_ATTRIBUTE_NAME, enabled, //
			KINDS_ATTRIBUTE_NAME, kinds = computeKinds(info), //
			DISPLAY_ATTRIBUTE_NAME, display = getDisplay() //
		), reason);
	}

	protected CompletableFuture<Void> updateInfo(JdiBreakpointInfo oldInfo,
			JdiBreakpointInfo newInfo, String reason) {
		this.info = newInfo;
		updateAttributesFromInfo(reason);
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getInfo(refresh).thenCompose(i -> {
			return updateInfo(info, i, "Refreshed");
		});
	}

	@Override
	public CompletableFuture<Void> disable() {
		info.setEnabled(false);
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> enable() {
		info.setEnabled(true);
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public String getDisplay() {
		return info == null ? super.getDisplay() : info.toString();
	}
}
