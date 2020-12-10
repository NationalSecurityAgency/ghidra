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
import java.util.stream.Collectors;

import org.apache.commons.lang3.tuple.Pair;

import agent.dbgeng.model.iface2.*;
import ghidra.dbg.target.TargetObject;
import ghidra.util.datastruct.WeakValueHashMap;

public class DbgModelTargetAvailableContainerImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetAvailableContainer {

	protected final Map<Integer, DbgModelTargetAvailable> attachablesById =
		new WeakValueHashMap<>();

	public DbgModelTargetAvailableContainerImpl(DbgModelTargetRoot root) {
		super(root.getModel(), root, "Available", "AvailableContainer");
		changeAttributes(List.of(), List.of(), Map.of( //
			UPDATE_MODE_ATTRIBUTE_NAME, TargetUpdateMode.SOLICITED //
		), "Initialized");
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getManager().listAvailableProcesses().thenAccept(list -> {
			List<TargetObject> available;
			synchronized (this) {
				// NOTE: If more details added to entries, should clear attachablesById
				available =
					list.stream().map(this::getTargetAttachableEx).collect(Collectors.toList());
			}
			setElements(available, Map.of(), "Refreshed");
		});
	}

	public synchronized DbgModelTargetAvailable getTargetAttachableEx(Pair<Integer, String> pair) {
		return attachablesById.computeIfAbsent(pair.getLeft(),
			i -> new DbgModelTargetAvailableImpl(this, pair.getLeft(), pair.getRight()));
	}

	@Override
	public synchronized DbgModelTargetAvailable getTargetAttachable(int pid) {
		return attachablesById.computeIfAbsent(pid,
			i -> new DbgModelTargetAvailableImpl(this, pid));
	}
}
