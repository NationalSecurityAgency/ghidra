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
import java.util.stream.Collectors;

import com.sun.jdi.Location;

import ghidra.dbg.jdi.manager.JdiCause;
import ghidra.dbg.jdi.manager.JdiEventsListenerAdapter;
import ghidra.dbg.jdi.manager.breakpoint.JdiBreakpointInfo;
import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.TargetBreakpointSpecContainer;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.schema.*;
import ghidra.program.model.address.AddressRange;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "BreakpointContainer",
	elements = {
		@TargetElementType(type = JdiModelTargetBreakpointSpec.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class JdiModelTargetBreakpointContainer extends JdiModelTargetObjectImpl implements
		TargetBreakpointSpecContainer, JdiEventsListenerAdapter {

	protected static final TargetBreakpointKindSet SUPPORTED_KINDS =
		TargetBreakpointKindSet.of(TargetBreakpointKind.values());

	protected final Map<JdiBreakpointInfo, JdiModelTargetBreakpointSpec> specsByInfo =
		new WeakValueHashMap<>();

	public JdiModelTargetBreakpointContainer(JdiModelTargetVM vm) {
		super(vm, "Breakpoints");

		impl.getManager().addEventsListener(null, this);

		changeAttributes(List.of(), List.of(), Map.of(  //
			// TODO: Seems terrible to duplicate this static attribute on each instance
			SUPPORTED_BREAK_KINDS_ATTRIBUTE_NAME, SUPPORTED_KINDS //
		), "Initialized");
	}

	@Override
	public void breakpointCreated(JdiBreakpointInfo info, JdiCause cause) {
		changeElements(List.of(), List.of(getTargetBreakpointSpec(info)), Map.of(), "Created");
	}

	@Override
	public void breakpointModified(JdiBreakpointInfo newInfo, JdiBreakpointInfo oldInfo,
			JdiCause cause) {
		getTargetBreakpointSpec(oldInfo).updateInfo(oldInfo, newInfo, "Modified");
	}

	@Override
	public void breakpointDeleted(JdiBreakpointInfo info, JdiCause cause) {
		synchronized (this) {
			specsByInfo.remove(info);
		}
		changeElements(List.of(info.toString()), List.of(), Map.of(), "Deleted");
	}

	@Override
	public CompletableFuture<Void> placeBreakpoint(AddressRange range,
			Set<TargetBreakpointKind> kinds) {
		if (kinds.contains(TargetBreakpointKind.SW_EXECUTE)) {
			Location location = impl.getLocation(range.getMinAddress());
			JdiModelTargetLocation targetLocation =
				(JdiModelTargetLocation) getTargetObject(location);
			if (targetLocation == null) {
				targetLocation = new JdiModelTargetLocation(this, location, true);
			}
			JdiBreakpointInfo info = targetLocation.addBreakpoint();
			breakpointCreated(info, JdiCause.Causes.UNCLAIMED);
		}
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> placeBreakpoint(String expression,
			Set<TargetBreakpointKind> kinds) {
		JdiModelTargetObject targetObject = getTargetObject(expression);
		if (targetObject != null) {
			if (kinds.contains(TargetBreakpointKind.SW_EXECUTE) &&
				targetObject instanceof JdiModelTargetLocation) {
				JdiModelTargetLocation targetLocation = (JdiModelTargetLocation) targetObject;
				JdiBreakpointInfo info = targetLocation.addBreakpoint();
				breakpointCreated(info, JdiCause.Causes.UNCLAIMED);
			}
			if ((kinds.contains(TargetBreakpointKind.READ) ||
				kinds.contains(TargetBreakpointKind.HW_EXECUTE)) &&
				targetObject instanceof JdiModelTargetField && targetVM.vm.canWatchFieldAccess()) {
				JdiModelTargetField targetField = (JdiModelTargetField) targetObject;
				JdiBreakpointInfo info = targetField.addAccessWatchpoint();
				breakpointCreated(info, JdiCause.Causes.UNCLAIMED);
			}
			if (kinds.contains(TargetBreakpointKind.WRITE) &&
				targetObject instanceof JdiModelTargetField &&
				targetVM.vm.canWatchFieldModification()) {
				JdiModelTargetField targetField = (JdiModelTargetField) targetObject;
				JdiBreakpointInfo info = targetField.addModificationWatchpoint();
				breakpointCreated(info, JdiCause.Causes.UNCLAIMED);
			}
		}
		return CompletableFuture.completedFuture(null);
	}

	public synchronized JdiModelTargetBreakpointSpec getTargetBreakpointSpec(
			JdiBreakpointInfo info) {
		return specsByInfo.computeIfAbsent(info,
			i -> new JdiModelTargetBreakpointSpec(this, info, true));
	}

	protected void updateUsingBreakpoints(Map<Long, JdiBreakpointInfo> byNumber) {
		List<JdiModelTargetBreakpointSpec> specs;
		synchronized (this) {
			specs = byNumber.values()
					.stream()
					.map(this::getTargetBreakpointSpec)
					.collect(Collectors.toList());
		}
		setElements(specs, Map.of(), "Refreshed");
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return CompletableFuture.completedFuture(null);
	}
}
