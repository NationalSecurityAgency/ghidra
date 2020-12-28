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
package agent.gdb.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.gdb.manager.GdbProcessThreadGroup;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(name = "AvailableContainer", attributes = {
	@TargetAttributeType(type = Void.class)
}, canonicalContainer = true)
public class GdbModelTargetAvailableContainer
		extends DefaultTargetObject<GdbModelTargetAttachable, GdbModelTargetSession> {
	public static final String NAME = "Available";

	protected final GdbModelImpl impl;

	protected final Map<Integer, GdbModelTargetAttachable> attachablesById =
		new WeakValueHashMap<>();

	public GdbModelTargetAvailableContainer(GdbModelTargetSession session) {
		super(session.impl, session, NAME, "AvailableContainer");
		this.impl = session.impl;
		changeAttributes(List.of(), Map.of(
			UPDATE_MODE_ATTRIBUTE_NAME, TargetUpdateMode.SOLICITED //
		), "Initialized");
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return impl.gdb.listAvailableProcesses().thenAccept(list -> {
			List<GdbModelTargetAttachable> available;
			synchronized (this) {
				// NOTE: If more details added to entries, should clear attachablesById
				available = list.stream()
						.map(this::getTargetAttachable)
						.collect(Collectors.toList());
			}
			setElements(available, "Refreshed");
		});
	}

	protected synchronized GdbModelTargetAttachable getTargetAttachable(
			GdbProcessThreadGroup process) {
		return attachablesById.computeIfAbsent(process.getPid(),
			i -> new GdbModelTargetAttachable(impl, this, process));
	}
}
